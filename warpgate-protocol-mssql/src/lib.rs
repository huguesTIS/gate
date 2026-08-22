//! Exploratory MSSQL (TDS) protocol groundwork.
//!
//! See `ARCHITECTURE_TECHNIQUE.md` §12 "MSSQL" for the decision this crate
//! implements: `tds-protocol` (IO-agnostic wire framing, `praxiomlabs/rust-mssql-driver`,
//! MIT/Apache-2.0) is a real upgrade over the `mssql-mock-tds` test fixture
//! evaluated earlier — collation-aware VARCHAR/NVARCHAR decoding, Always
//! Encrypted metadata, TVP, RPC, CI'd against real SQL Server 2017/2019/2022 —
//! but it's client-only itself (`mssql-client`), so building a *server* still
//! needs our own code on top, mirroring the `mysql_common`-plus-our-own-server
//! pattern `warpgate-protocol-mysql` already uses.
//!
//! This crate is not yet a dependency of the `warpgate` binary. It's a
//! workspace member so `cargo check -p warpgate-protocol-mssql` builds in
//! isolation (no `warpgate-core`/full-binary recompile) while the low-level
//! handshake is proven out against a real Dockerized SQL Server.

mod login7_decode;
mod server_tokens;

use bytes::{Bytes, BytesMut};
pub use login7_decode::decode_login7;
pub use server_tokens::{build_login_failure_response, build_login_success_response};
use tds_protocol::{
    ColMetaData, EncryptionLevel, Login7, PacketHeader, PacketStatus, PacketType, PreLogin,
    SqlBatch, Token, TokenParser,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, thiserror::Error)]
pub enum MssqlError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] tds_protocol::ProtocolError),
    #[error("server response was not a PreLogin-shaped packet (got type {0:?}): {1}")]
    UnexpectedPacketType(tds_protocol::PacketType, String),
    #[error("login rejected: {0}")]
    LoginRejected(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
    #[error("malformed LOGIN7 packet: {0}")]
    MalformedLogin7(String),
}

/// Result of a `SqlBatch`, deliberately shallow: this milestone proves the
/// `SqlBatch` → `ColMetaData` → `Row`/`NbcRow` → `Done` token sequence
/// round-trips against a real server, not a full typed row decoder — `RawRow`
/// only exposes the wire-encoded bytes per row (`tds-protocol` is explicit
/// that per-type decoding is the caller's job). Typed value extraction is
/// future work once there's a real proxying architecture to decode *into*.
#[derive(Debug)]
pub struct QueryResult {
    pub column_names: Vec<String>,
    pub row_count: usize,
    /// Rows actually affected/returned, per the server's own `DONE` token —
    /// compared against `row_count` (rows this crate actually saw) as a
    /// consistency check, not just trusted blindly.
    pub done_row_count: Option<u64>,
}

/// Best-effort extraction of a `Token::Error`'s message from an unexpected
/// packet body, for diagnostics when the server rejects something before we
/// even reach a normal response — e.g. a malformed request on our side.
fn describe_unexpected_packet(body: Bytes) -> String {
    let mut parser = TokenParser::new(body);
    match parser.next_token() {
        Ok(Some(Token::Error(err))) => {
            format!("server error {} (state {}): {}", err.number, err.state, err.message)
        }
        Ok(Some(token)) => format!("first token was {token:?}, not an error"),
        Ok(None) => "empty token stream".to_string(),
        Err(e) => format!("failed to parse token stream: {e}"),
    }
}

/// Writes one TDS packet: header + payload, single message (`END_OF_MESSAGE`
/// set on the only packet). Every request this crate sends so far fits in one
/// packet, well under `DEFAULT_PACKET_SIZE`.
async fn write_tds_message(
    stream: &mut TcpStream,
    packet_type: PacketType,
    payload: &[u8],
) -> Result<(), MssqlError> {
    let header = PacketHeader::new(
        packet_type,
        PacketStatus::END_OF_MESSAGE,
        (tds_protocol::PACKET_HEADER_SIZE + payload.len()) as u16,
    );
    let mut out = BytesMut::with_capacity(header.length as usize);
    header.encode(&mut out);
    out.extend_from_slice(payload);
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}

/// Reads one full TDS *message* — one or more packets, concatenated, until a
/// packet header sets `END_OF_MESSAGE`. A LOGINACK response (LOGINACK +
/// ENVCHANGE + INFO + DONE tokens) can in principle span multiple packets
/// once a real database/collation is attached, even though today's PreLogin
/// and simple-auth responses fit in one; reading this way now avoids a silent
/// truncation bug once that stops being true.
async fn read_tds_message(stream: &mut TcpStream) -> Result<(PacketType, Bytes), MssqlError> {
    let mut full_body = BytesMut::new();
    let mut packet_type = None;
    loop {
        let mut header_buf = [0u8; tds_protocol::PACKET_HEADER_SIZE];
        stream.read_exact(&mut header_buf).await?;
        let header = PacketHeader::decode(&mut &header_buf[..])?;
        if packet_type.is_none() {
            packet_type = Some(header.packet_type);
        }

        let body_len = header.length as usize - tds_protocol::PACKET_HEADER_SIZE;
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).await?;
        full_body.extend_from_slice(&body);

        if header.status.contains(PacketStatus::END_OF_MESSAGE) {
            break;
        }
    }
    // A packet_type is always set: the loop above always executes at least
    // once before it can break, so this only fails to unwrap if the server
    // sends zero packets — which read_exact would already have errored on.
    Ok((packet_type.unwrap_or(PacketType::TabularResult), full_body.freeze()))
}

/// Sends a client PreLogin request over `stream` and returns the server's
/// decoded response. `requested_encryption` is this crate's own choice, not
/// necessarily what gets negotiated — the server may still report a
/// different level in its response; the caller must honor *that* (e.g. by
/// wrapping the connection in TLS before continuing) rather than what it
/// asked for. TLS-in-TDS isn't implemented yet, so callers should request
/// [`EncryptionLevel::NotSupported`] until it is — asking for anything the
/// server insists on encrypting will fail the next step (LOGIN7 sent in the
/// clear when the server expects a TLS ClientHello first).
///
/// This is the client side of the handshake (dialing a real backend as if we
/// were the proxied client) — proves `tds-protocol`'s encode/decode against a
/// real server before any server-side (listener) code is written.
pub async fn client_prelogin_handshake(
    stream: &mut TcpStream,
    requested_encryption: EncryptionLevel,
) -> Result<PreLogin, MssqlError> {
    let request = PreLogin::new().with_encryption(requested_encryption);
    let payload = request.encode();
    write_tds_message(stream, PacketType::PreLogin, &payload).await?;

    let (packet_type, body) = read_tds_message(stream).await?;

    // Real SQL Server labels its PreLogin *response* with the TabularResult
    // packet type (0x04), not PreLogin (0x12) — confirmed against a live
    // SQL Server 2022 container: the body decodes cleanly as a PreLogin
    // response (product version, encryption, MARS) even though the header
    // says TabularResult. MS-TDS itself doesn't document this distinctly
    // from a real query-result/error stream; a client is expected to know
    // from protocol state (it just sent PreLogin) which one it's reading.
    // Anything else genuinely is unexpected and gets the token-stream error
    // decoded for diagnostics.
    if !matches!(packet_type, PacketType::PreLogin | PacketType::TabularResult) {
        let detail = describe_unexpected_packet(body);
        return Err(MssqlError::UnexpectedPacketType(packet_type, detail));
    }

    Ok(PreLogin::decode(body.as_ref())?)
}

/// Reads and decodes a client's PreLogin request. Server-side counterpart to
/// [`client_prelogin_handshake`]'s outbound half — the first piece of the
/// *listener* side of the protocol (accepting a connection), as opposed to
/// every function above, which dials one. `tds-protocol`'s `PreLogin::decode`
/// is direction-agnostic (used here for the request, above for the response),
/// so no new wire-format code was needed for this half — unlike LOGIN7 below.
pub async fn server_read_prelogin(stream: &mut TcpStream) -> Result<PreLogin, MssqlError> {
    let (packet_type, body) = read_tds_message(stream).await?;
    if packet_type != PacketType::PreLogin {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a PreLogin request from the client".to_string(),
        ));
    }
    Ok(PreLogin::decode(body.as_ref())?)
}

/// Sends `response` as a PreLogin reply to a connecting client. Matches real
/// SQL Server's wire behavior discovered in [`client_prelogin_handshake`]'s
/// docs: the response packet is labeled `TabularResult` (0x04), not
/// `PreLogin` (0x12) — any real client, including this crate's own
/// `client_prelogin_handshake`, expects that.
pub async fn server_send_prelogin_response(
    stream: &mut TcpStream,
    response: &PreLogin,
) -> Result<(), MssqlError> {
    write_tds_message(stream, PacketType::TabularResult, &response.encode()).await
}

/// Reads and decodes a client's LOGIN7 request — a real gap `tds-protocol`
/// leaves open (no `Login7::decode()` at all, see [`login7_decode`]'s module
/// docs for why and how this fills it in by hand against MS-TDS directly).
///
/// Only gets the credentials off the wire; does not check them or send a
/// response — see [`server_authenticate_sql`] for the full request-check-
/// respond flow.
pub async fn server_read_login7(stream: &mut TcpStream) -> Result<Login7, MssqlError> {
    let (packet_type, body) = read_tds_message(stream).await?;
    if packet_type != PacketType::Tds7Login {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a LOGIN7 request from the client".to_string(),
        ));
    }
    decode_login7(&body)
}

/// Reads a client's LOGIN7 request and checks it against
/// `expected_username`/`expected_password`, sending LOGINACK (success) or
/// Error (failure) plus a trailing DONE token either way — see
/// [`server_tokens`]'s module docs for how those responses are built (the
/// other half of the gap `tds-protocol` leaves for LOGIN7: no `LoginAck`/
/// `Error` encoder either).
///
/// The equality check itself is a placeholder for this milestone, **not**
/// real credential verification — no Warpgate `ConfigProvider`/auth
/// integration exists yet (this crate isn't even a dependency of `warpgate`
/// — see the crate-level docs). Returns whether the login succeeded.
pub async fn server_authenticate_sql(
    stream: &mut TcpStream,
    expected_username: &str,
    expected_password: &str,
) -> Result<bool, MssqlError> {
    let login = server_read_login7(stream).await?;
    if login.username == expected_username && login.password == expected_password {
        let response = build_login_success_response(login.tds_version.raw());
        write_tds_message(stream, PacketType::TabularResult, &response).await?;
        Ok(true)
    } else {
        let response = build_login_failure_response("Login failed for user");
        write_tds_message(stream, PacketType::TabularResult, &response).await?;
        Ok(false)
    }
}

/// Sends a LOGIN7 packet authenticating as `username`/`password` (SQL
/// authentication, not Windows/Kerberos) and consumes the server's response
/// looking for a `LOGINACK` token. **Must** be called right after a
/// [`client_prelogin_handshake`] that negotiated no encryption — this sends
/// LOGIN7 (and the password inside it, only TDS-obfuscated, not encrypted;
/// see `tds_protocol::login7`'s module docs) in the clear.
pub async fn client_login7_sql_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<(), MssqlError> {
    let login = Login7::new().with_sql_auth(username, password);
    let payload = login.encode();
    write_tds_message(stream, PacketType::Tds7Login, &payload).await?;

    let (packet_type, body) = read_tds_message(stream).await?;
    if packet_type != PacketType::TabularResult {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a TabularResult LOGIN7 response".to_string(),
        ));
    }

    let mut parser = TokenParser::new(body);
    while let Some(token) = parser.next_token()? {
        match token {
            Token::Error(err) => {
                return Err(MssqlError::LoginRejected(format!(
                    "{} (state {}): {}",
                    err.number, err.state, err.message
                )));
            }
            Token::LoginAck(_) => return Ok(()),
            _ => {}
        }
    }
    Err(MssqlError::LoginRejected(
        "response contained no LOGINACK token".to_string(),
    ))
}

/// Sends `sql` as a `SqlBatch` request and reads the response, counting rows
/// and collecting column names. **Must** be called after a successful
/// [`client_login7_sql_auth`] on the same connection.
pub async fn client_sql_batch(stream: &mut TcpStream, sql: &str) -> Result<QueryResult, MssqlError> {
    let payload = SqlBatch::new(sql).encode();
    write_tds_message(stream, PacketType::SqlBatch, &payload).await?;

    let (packet_type, body) = read_tds_message(stream).await?;
    if packet_type != PacketType::TabularResult {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a TabularResult SqlBatch response".to_string(),
        ));
    }

    let mut parser = TokenParser::new(body);
    let mut metadata: Option<ColMetaData> = None;
    let mut column_names = Vec::new();
    let mut row_count = 0usize;
    let mut done_row_count = None;

    while let Some(token) = parser.next_token_with_metadata(metadata.as_ref())? {
        match token {
            Token::ColMetaData(md) => {
                column_names = md.columns.iter().map(|c| c.name.clone()).collect();
                metadata = Some(md);
            }
            Token::Row(_) | Token::NbcRow(_) => row_count += 1,
            Token::Done(done) if done.status.count => done_row_count = Some(done.row_count),
            Token::Error(err) => {
                return Err(MssqlError::QueryFailed(format!(
                    "{} (state {}): {}",
                    err.number, err.state, err.message
                )));
            }
            _ => {}
        }
    }

    Ok(QueryResult { column_names, row_count, done_row_count })
}

#[cfg(test)]
mod tests {
    //! Most tests here need a real SQL Server reachable at
    //! `WARPGATE_MSSQL_TEST_ADDR` (default `127.0.0.1:14330`, matching the
    //! throwaway container this crate was developed against — see
    //! `ARCHITECTURE_TECHNIQUE.md` §12). Same "needs a live server"
    //! limitation `ldap_group`'s tests already have — not run as part of the
    //! default `cross test` sweep, opt in with: `WARPGATE_MSSQL_TEST=1 cross
    //! test -p warpgate-protocol-mssql`.
    //!
    //! `WARPGATE_MSSQL_TEST_SA_PASSWORD` must match the container's
    //! `MSSQL_SA_PASSWORD` for the login tests.
    //!
    //! The `server_*` round-trip test is the exception — pure loopback
    //! against our own listener, no live server or env vars needed, runs
    //! every time.

    use super::*;

    #[tokio::test]
    async fn server_prelogin_round_trips_with_our_own_client() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let client_request = server_read_prelogin(&mut stream)
                .await
                .expect("decode client's PreLogin request");
            assert_eq!(client_request.encryption, EncryptionLevel::NotSupported);

            let response = PreLogin::new().with_encryption(EncryptionLevel::NotSupported);
            server_send_prelogin_response(&mut stream, &response)
                .await
                .expect("send PreLogin response");
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our own server");
        let response = client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake against our own server");

        server_task.await.expect("server task panicked");
        assert_eq!(response.encryption, EncryptionLevel::NotSupported);
    }

    /// Proves the hand-written `decode_login7` against a real `Login7::encode()`
    /// output — not our own re-implementation of encoding, `tds-protocol`'s
    /// actual encoder. No live server or LOGINACK response needed: this only
    /// tests the request-decoding half (see `server_read_login7`'s docs for
    /// why the response half is a separate, still-open gap).
    #[tokio::test]
    async fn server_login7_decodes_a_real_client_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            server_read_login7(&mut stream).await.expect("decode client's LOGIN7 request")
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our own server");
        let login = Login7::new()
            .with_hostname("test-host")
            .with_sql_auth("someuser", "s3cr3t-p@ss")
            .with_app_name("warpgate-protocol-mssql-test")
            .with_database("mydb");
        write_tds_message(&mut client_stream, PacketType::Tds7Login, &login.encode())
            .await
            .expect("send LOGIN7");

        let decoded = server_task.await.expect("server task panicked");

        assert_eq!(decoded.hostname, "test-host");
        assert_eq!(decoded.username, "someuser");
        assert_eq!(decoded.password, "s3cr3t-p@ss");
        assert_eq!(decoded.app_name, "warpgate-protocol-mssql-test");
        assert_eq!(decoded.database, "mydb");
        assert!(!decoded.option_flags2.integrated_security, "with_sql_auth must clear integrated_security");
    }

    /// The full loop closed: this crate's own `client_prelogin_handshake` +
    /// `client_login7_sql_auth` against this crate's own
    /// `server_read_prelogin`/`server_send_prelogin_response` +
    /// `server_authenticate_sql` — first time both directions of the
    /// handshake interoperate. Pure loopback, no Docker container.
    #[tokio::test]
    async fn server_authenticates_a_client_with_matching_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            server_read_prelogin(&mut stream).await.expect("decode PreLogin");
            server_send_prelogin_response(
                &mut stream,
                &PreLogin::new().with_encryption(EncryptionLevel::NotSupported),
            )
            .await
            .expect("send PreLogin response");

            server_authenticate_sql(&mut stream, "sa", "correct-horse-battery-staple")
                .await
                .expect("authenticate")
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our own server");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake");
        client_login7_sql_auth(&mut client_stream, "sa", "correct-horse-battery-staple")
            .await
            .expect("LOGIN7 with matching credentials should succeed");

        assert!(server_task.await.expect("server task panicked"));
    }

    #[tokio::test]
    async fn server_rejects_a_client_with_wrong_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            server_read_prelogin(&mut stream).await.expect("decode PreLogin");
            server_send_prelogin_response(
                &mut stream,
                &PreLogin::new().with_encryption(EncryptionLevel::NotSupported),
            )
            .await
            .expect("send PreLogin response");

            server_authenticate_sql(&mut stream, "sa", "correct-horse-battery-staple")
                .await
                .expect("authenticate")
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our own server");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake");
        let result = client_login7_sql_auth(&mut client_stream, "sa", "wrong-password").await;

        assert!(
            matches!(result, Err(MssqlError::LoginRejected(_))),
            "wrong password must be rejected as LoginRejected, got {result:?}"
        );
        assert!(!server_task.await.expect("server task panicked"));
    }

    async fn connect() -> TcpStream {
        let addr = std::env::var("WARPGATE_MSSQL_TEST_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:14330".to_string());
        TcpStream::connect(&addr)
            .await
            .unwrap_or_else(|e| panic!("connect to {addr}: {e}"))
    }

    fn live_test_enabled() -> bool {
        std::env::var("WARPGATE_MSSQL_TEST").is_ok()
    }

    #[tokio::test]
    async fn completes_prelogin_against_a_real_sql_server() {
        if !live_test_enabled() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let mut stream = connect().await;

        let response = client_prelogin_handshake(&mut stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake");

        assert!(
            response.server_version.is_some(),
            "a real SQL Server must report its product version in PreLogin"
        );
    }

    #[tokio::test]
    async fn logs_in_with_valid_sql_credentials() {
        if !live_test_enabled() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let password = std::env::var("WARPGATE_MSSQL_TEST_SA_PASSWORD")
            .expect("WARPGATE_MSSQL_TEST_SA_PASSWORD must be set for the login test");
        let mut stream = connect().await;

        client_prelogin_handshake(&mut stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake");
        client_login7_sql_auth(&mut stream, "sa", &password)
            .await
            .expect("LOGIN7 with valid credentials should succeed");
    }

    #[tokio::test]
    async fn runs_a_simple_select_and_reads_the_result_shape() {
        if !live_test_enabled() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let password = std::env::var("WARPGATE_MSSQL_TEST_SA_PASSWORD")
            .expect("WARPGATE_MSSQL_TEST_SA_PASSWORD must be set for the login test");
        let mut stream = connect().await;

        client_prelogin_handshake(&mut stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake");
        client_login7_sql_auth(&mut stream, "sa", &password)
            .await
            .expect("LOGIN7 with valid credentials should succeed");

        let result = client_sql_batch(&mut stream, "SELECT 1 AS n")
            .await
            .expect("SELECT 1 should succeed");

        assert_eq!(result.column_names, vec!["n".to_string()]);
        assert_eq!(result.row_count, 1);
        assert_eq!(result.done_row_count, Some(1));
    }

    #[tokio::test]
    async fn rejects_wrong_password() {
        if !live_test_enabled() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let mut stream = connect().await;

        client_prelogin_handshake(&mut stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake");
        let result = client_login7_sql_auth(&mut stream, "sa", "definitely-the-wrong-password").await;

        assert!(
            matches!(result, Err(MssqlError::LoginRejected(_))),
            "a wrong password must be rejected as LoginRejected, got {result:?}"
        );
    }
}

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
//!
//! Every function below that touches the wire is generic over
//! `impl AsyncRead + AsyncWrite + Unpin` rather than hardcoded to
//! `TcpStream` — the point being TLS-in-TDS (see [`client_upgrade_to_tls`]):
//! a `TlsStream<TlsPreloginWrapper<TcpStream>>` satisfies the same bound, so
//! `client_login7_sql_auth`/`client_sql_batch`/`run_proxy_session`/etc. work
//! unchanged over an encrypted connection, no separate encrypted-path copies
//! of any of this logic needed.

mod login7_decode;
mod server_tokens;

use bytes::{Bytes, BytesMut};
pub use login7_decode::decode_login7;
use mssql_tls::{TlsConfig, TlsConnector, TlsPreloginWrapper};
pub use server_tokens::{build_login_failure_response, build_login_success_response};
use tds_protocol::{
    ColMetaData, EncryptionLevel, Login7, PacketHeader, PacketStatus, PacketType, PreLogin,
    SqlBatch, Token, TokenParser,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    #[error("malformed SqlBatch packet: {0}")]
    MalformedSqlBatch(String),
    #[error("TLS error: {0}")]
    Tls(#[from] mssql_tls::TlsError),
    #[error("server does not support encryption, cannot upgrade to TLS")]
    EncryptionNotSupported,
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
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
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
async fn read_tds_message(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<(PacketType, Bytes), MssqlError> {
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
/// wrapping the connection in TLS before continuing, see
/// [`client_upgrade_to_tls`]) rather than what it asked for.
///
/// This is the client side of the handshake (dialing a real backend as if we
/// were the proxied client) — proves `tds-protocol`'s encode/decode against a
/// real server before any server-side (listener) code is written.
pub async fn client_prelogin_handshake(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
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

/// Upgrades `stream` to TLS, TDS 7.x style: the handshake is wrapped inside
/// `PreLogin`-typed packets rather than sent as raw TLS records — real SQL
/// Server (and any real client) expects that; see
/// `mssql_tls::TlsPreloginWrapper`'s module docs. **Must** be called right
/// after a [`client_prelogin_handshake`] whose response indicated the server
/// supports encryption (`response.encryption.is_required()`, or plain `On`)
/// — calling this against a server that answered `NotSupported`/`Off` sends
/// a TLS ClientHello the server isn't expecting.
///
/// `trust_server_certificate` skips certificate validation entirely —
/// `mssql-tls`'s own docs are explicit this is for development only (e.g.
/// against a throwaway Docker container's self-generated cert, which is all
/// this crate has been tested against so far). A real deployment needs a
/// real CA or an explicit pinned certificate instead.
///
/// Consumes `stream` and returns the TLS-wrapped replacement — every
/// function in this crate taking `impl AsyncRead + AsyncWrite + Unpin`
/// (LOGIN7, SqlBatch, the proxy session loop, all of it) works unchanged
/// against what this returns, no separate encrypted-path logic needed.
pub async fn client_upgrade_to_tls<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    server_name: &str,
    trust_server_certificate: bool,
) -> Result<mssql_tls::TlsStream<TlsPreloginWrapper<S>>, MssqlError> {
    let config = TlsConfig::new().trust_server_certificate(trust_server_certificate);
    let connector = TlsConnector::new(config)?;
    Ok(connector.connect_with_prelogin(stream, server_name).await?)
}

/// Reads and decodes a client's PreLogin request. Server-side counterpart to
/// [`client_prelogin_handshake`]'s outbound half — the first piece of the
/// *listener* side of the protocol (accepting a connection), as opposed to
/// every function above, which dials one. `tds-protocol`'s `PreLogin::decode`
/// is direction-agnostic (used here for the request, above for the response),
/// so no new wire-format code was needed for this half — unlike LOGIN7 below.
pub async fn server_read_prelogin(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<PreLogin, MssqlError> {
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
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    response: &PreLogin,
) -> Result<(), MssqlError> {
    write_tds_message(stream, PacketType::TabularResult, &response.encode()).await
}

/// Upgrades an accepted connection to TLS, TDS 7.x style — the server-side
/// counterpart to [`client_upgrade_to_tls`]. **Must** be called right after
/// [`server_send_prelogin_response`] sent a response indicating encryption
/// (mirrors the client side's requirement).
///
/// `mssql-tls` is a client-only crate (see the crate docs), so it has no
/// `TlsAcceptor` of its own — but `TlsPreloginWrapper` (the piece that
/// wraps/unwraps the TLS handshake inside `PreLogin` packets) is direction-
/// agnostic, a plain `AsyncRead`/`AsyncWrite` adapter with no client-specific
/// logic in it, so it works unchanged with a caller-supplied
/// `tokio_rustls::TlsAcceptor` instead of `mssql-tls`'s `TlsConnector`. The
/// `TlsAcceptor` itself (and the certificate/key behind it) is the caller's
/// responsibility — a real deployment needs a real certificate, not
/// something this crate should generate.
///
/// **`acceptor` must be restricted to TLS 1.2** (e.g.
/// `ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])`).
/// TLS 1.3 hits a real, reproduced bug in `mssql-tls`'s `TlsPreloginWrapper`
/// when driven by a `TlsAcceptor` (as opposed to `TlsConnector`, the only
/// role its own test suite exercises): the connection breaks with a
/// `rustls` `InvalidContentType` error on the very first message sent after
/// the handshake. Root-caused via wire-level tracing to TLS 1.3's
/// server-sent post-handshake `NewSessionTicket` — forcing TLS 1.2 (which
/// has no such message) makes the failure disappear completely and
/// repeatably; see `server_accepts_a_tls_client_and_completes_login`'s test
/// doc comment for the full writeup. Not something to work around inside
/// this crate — it's an upstream bug in code we don't own.
pub async fn server_upgrade_to_tls<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    acceptor: &tokio_rustls::TlsAcceptor,
) -> Result<tokio_rustls::server::TlsStream<TlsPreloginWrapper<S>>, MssqlError> {
    let wrapper = TlsPreloginWrapper::new(stream);
    let mut tls_stream = acceptor.accept(wrapper).await?;
    // get_mut() returns (&mut IO, &mut ServerConnection) — same shape as the
    // client-side TlsStream mssql-tls's own connect_with_prelogin() uses;
    // .0 is our wrapper.
    tls_stream.get_mut().0.handshake_complete();
    Ok(tls_stream)
}

/// Reads and decodes a client's LOGIN7 request — a real gap `tds-protocol`
/// leaves open (no `Login7::decode()` at all, see [`login7_decode`]'s module
/// docs for why and how this fills it in by hand against MS-TDS directly).
///
/// Only gets the credentials off the wire; does not check them or send a
/// response — see [`server_authenticate_sql`] for the full request-check-
/// respond flow.
pub async fn server_read_login7(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<Login7, MssqlError> {
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
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    expected_username: &str,
    expected_password: &str,
) -> Result<bool, MssqlError> {
    server_authenticate_with(stream, |username, password| {
        username == expected_username && password == expected_password
    })
    .await
}

/// Same as [`server_authenticate_sql`], but with the credential check
/// supplied by the caller instead of a fixed username/password — what
/// [`run_proxy_session`] uses, since a real deployment needs to check
/// against Warpgate's own auth, not one hardcoded pair.
pub async fn server_authenticate_with(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    check_credentials: impl FnOnce(&str, &str) -> bool,
) -> Result<bool, MssqlError> {
    let login = server_read_login7(stream).await?;
    if check_credentials(&login.username, &login.password) {
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
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
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
pub async fn client_sql_batch(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), sql: &str) -> Result<QueryResult, MssqlError> {
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

/// Decodes a `SqlBatch` request body — another gap `tds-protocol` leaves
/// open (`SqlBatch` only has `encode()`, same client-only asymmetry as
/// LOGIN7 and the LOGINACK/Error tokens, but simpler to fill: no offset
/// table, just a fixed 22-byte `ALL_HEADERS` prefix (verified against
/// `sealed::encode_sql_batch_with_transaction`'s source and its own golden-
/// byte test) followed by the SQL text as raw UTF-16LE running to the end of
/// the packet — no length prefix needed since packet framing already gives
/// the total length.
fn decode_sql_batch(data: &[u8]) -> Result<String, MssqlError> {
    const ALL_HEADERS_SIZE: usize = 22;
    let Some(sql_bytes) = data.get(ALL_HEADERS_SIZE..) else {
        return Err(MssqlError::MalformedSqlBatch(format!(
            "SqlBatch payload is {} bytes, need at least the {ALL_HEADERS_SIZE}-byte ALL_HEADERS prefix",
            data.len()
        )));
    };
    if sql_bytes.len() % 2 != 0 {
        return Err(MssqlError::MalformedSqlBatch(
            "SQL text is not a whole number of UTF-16LE code units".to_string(),
        ));
    }
    let units: Vec<u16> =
        sql_bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Reads and decodes a client's `SqlBatch` request, returning the SQL text.
pub async fn server_read_sql_batch(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<String, MssqlError> {
    let (packet_type, body) = read_tds_message(stream).await?;
    if packet_type != PacketType::SqlBatch {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a SqlBatch request from the client".to_string(),
        ));
    }
    decode_sql_batch(&body)
}

/// Runs `sql` against `backend` (an already-authenticated TDS connection to
/// a real target, e.g. via [`client_prelogin_handshake`] +
/// [`client_login7_sql_auth`]) and relays the backend's response bytes
/// straight through to `frontend` as a `TabularResult` packet.
///
/// This is the actual proxying mechanism: no `ColMetaData`/`Row` *encoder*
/// is needed (a much bigger gap than LOGIN7's — real per-column-type
/// encoding, not a fixed-size header) because a proxy never needs to
/// understand a result set's contents, only forward it byte for byte. Every
/// real client, including this crate's own [`client_sql_batch`], parses the
/// relayed bytes exactly as if they came straight from the backend, because
/// they did.
pub async fn relay_sql_batch(
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    frontend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    sql: &str,
) -> Result<(), MssqlError> {
    let payload = SqlBatch::new(sql).encode();
    write_tds_message(backend, PacketType::SqlBatch, &payload).await?;

    let (packet_type, body) = read_tds_message(backend).await?;
    if packet_type != PacketType::TabularResult {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a TabularResult SqlBatch response from the backend".to_string(),
        ));
    }

    write_tds_message(frontend, PacketType::TabularResult, &body).await
}

/// Runs a full proxy session on `frontend`: the PreLogin + LOGIN7 handshake
/// (`check_credentials` decides success — see [`server_authenticate_with`]),
/// then loops relaying `SqlBatch` requests to `backend` (already connected
/// and authenticated by the caller) until `frontend` disconnects.
///
/// Only `SqlBatch` is handled — any other packet type ends the session with
/// [`MssqlError::UnexpectedPacketType`]. A clean disconnect (the frontend
/// closing the connection between requests) ends the loop with `Ok(())`, not
/// an error; anything else reading the next request is propagated as a real
/// error. This doesn't yet distinguish "closed between requests" from
/// "closed mid-packet" — both surface as the same `UnexpectedEof`, treated
/// the same way (session over) — good enough for this milestone, worth
/// splitting only if a real deployment needs to tell the two apart.
pub async fn run_proxy_session(
    frontend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    requested_encryption: EncryptionLevel,
    check_credentials: impl FnOnce(&str, &str) -> bool,
) -> Result<(), MssqlError> {
    server_read_prelogin(frontend).await?;
    server_send_prelogin_response(
        frontend,
        &PreLogin::new().with_encryption(requested_encryption),
    )
    .await?;

    if !server_authenticate_with(frontend, check_credentials).await? {
        return Err(MssqlError::LoginRejected(
            "credential check failed".to_string(),
        ));
    }

    loop {
        let (packet_type, body) = match read_tds_message(frontend).await {
            Ok(message) => message,
            Err(MssqlError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        match packet_type {
            PacketType::SqlBatch => {
                let sql = decode_sql_batch(&body)?;
                relay_sql_batch(backend, frontend, &sql).await?;
            }
            other => {
                return Err(MssqlError::UnexpectedPacketType(
                    other,
                    "unsupported packet type in proxy session (only SqlBatch handled so far)"
                        .to_string(),
                ));
            }
        }
    }
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

    use tokio::net::TcpStream;

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

    /// `server_upgrade_to_tls` against `client_upgrade_to_tls` — the server
    /// side of TLS-in-TDS, proven the same way the client side was: pure
    /// loopback, no Docker container, with a throwaway self-signed
    /// certificate generated on the fly (`rcgen`, same crate the rest of
    /// this codebase already uses for exactly this — see
    /// `warpgate/src/commands/setup.rs`). PreLogin negotiates encryption in
    /// the clear first, matching TDS 7.x and how a real proxy session would
    /// need to sequence this — only *then* does either side upgrade.
    ///
    /// **Real bug found and root-caused in `mssql-tls` itself, not this
    /// crate**: with TLS 1.3 (the default — `TlsConfig`/`ServerConfig`
    /// otherwise both allow 1.2 and 1.3), the connection consistently broke
    /// with a `rustls` `InvalidContentType` error on the very first message
    /// sent after the handshake (LOGIN7), specifically when
    /// `TlsPreloginWrapper` is driven by a `TlsAcceptor` (server role) rather
    /// than `mssql-tls`'s own `TlsConnector` (client role, the only role the
    /// crate's own test suite exercises). Traced with wire-level logging: the
    /// client had already flushed its post-handshake LOGIN7 by the time the
    /// server's handshake future even resolved, meaning TLS 1.3's
    /// server-sent post-handshake `NewSessionTicket` message was still in
    /// flight/unprocessed when `handshake_complete()` flips the wrapper to
    /// passthrough — the likely mechanism: leftover partially-read
    /// `TlsPreloginWrapper` header/payload state gets stranded and the next
    /// passthrough read starts at the wrong stream offset. Forcing TLS 1.2
    /// (no post-handshake `NewSessionTicket`) makes the failure disappear
    /// completely and repeatably — strong confirmation, not a guess.
    /// Workaround: pin the server side to TLS 1.2 via
    /// `ServerConfig::builder_with_protocol_versions`, documented here rather
    /// than silently — a real deployment needing 1.3 will hit this until
    /// it's fixed upstream or a different TLS-in-TDS implementation is used
    /// for the server side.
    #[tokio::test]
    async fn server_accepts_a_tls_client_and_completes_login() {
        // mssql-tls installs this too (see its connector module), but the
        // server and client tasks below race to be first, so install it
        // explicitly up front rather than relying on which one wins.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate a throwaway self-signed certificate");
        let cert_der = cert.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        // TLS 1.2 only — see this test's doc comment for the TLS 1.3 bug in
        // mssql-tls's TlsPreloginWrapper this works around.
        let server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("build a rustls ServerConfig from the throwaway cert");
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut raw_stream, _) = listener.accept().await.expect("accept");
            server_read_prelogin(&mut raw_stream).await.expect("decode client's PreLogin");
            server_send_prelogin_response(
                &mut raw_stream,
                &PreLogin::new().with_encryption(EncryptionLevel::On),
            )
            .await
            .expect("send PreLogin response");

            let mut tls_stream = server_upgrade_to_tls(raw_stream, &acceptor)
                .await
                .expect("server-side TLS handshake");

            server_authenticate_with(&mut tls_stream, |u, p| u == "tlsuser" && p == "tlspass")
                .await
                .expect("authenticate over TLS")
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our own server");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::Required)
            .await
            .expect("PreLogin handshake requesting encryption");

        let mut client_tls_stream = client_upgrade_to_tls(client_stream, "localhost", true)
            .await
            .expect("client-side TLS handshake");
        client_login7_sql_auth(&mut client_tls_stream, "tlsuser", "tlspass")
            .await
            .expect("LOGIN7 over TLS against our own server should succeed");

        assert!(server_task.await.expect("server task panicked"));
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

    /// TLS-in-TDS, proven against the real container: PreLogin requesting
    /// encryption (unlike every other live test here, which requests
    /// `NotSupported` specifically to stay in the clear), then
    /// `client_upgrade_to_tls`, then LOGIN7 and a query *over the TLS
    /// stream* using the exact same `client_login7_sql_auth`/
    /// `client_sql_batch` functions the plaintext tests use — proving the
    /// generic `impl AsyncRead + AsyncWrite + Unpin` refactor actually pays
    /// off, not just compiles.
    #[tokio::test]
    async fn logs_in_over_tls_against_a_real_sql_server() {
        if !live_test_enabled() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let password = std::env::var("WARPGATE_MSSQL_TEST_SA_PASSWORD")
            .expect("WARPGATE_MSSQL_TEST_SA_PASSWORD must be set for the login test");
        let mut stream = connect().await;

        let response = client_prelogin_handshake(&mut stream, EncryptionLevel::Required)
            .await
            .expect("PreLogin handshake requesting encryption");
        assert!(
            response.encryption.is_required() || response.encryption == EncryptionLevel::On,
            "expected the server to support encryption, got {:?}",
            response.encryption
        );

        let mut tls_stream = client_upgrade_to_tls(stream, "localhost", true)
            .await
            .expect("TLS handshake (TDS 7.x, PreLogin-wrapped)");

        client_login7_sql_auth(&mut tls_stream, "sa", &password)
            .await
            .expect("LOGIN7 over TLS should succeed");

        let result = client_sql_batch(&mut tls_stream, "SELECT 1 AS n")
            .await
            .expect("SELECT 1 over TLS should succeed");
        assert_eq!(result.column_names, vec!["n".to_string()]);
        assert_eq!(result.done_row_count, Some(1));
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

    /// The actual proxy round trip, for the first time: a test client talks
    /// only to our own server; our server is the only one that talks to the
    /// real SQL Server container. `client_sql_batch` — the exact same
    /// function `runs_a_simple_select_and_reads_the_result_shape` uses
    /// directly against the real container above — is reused here unchanged
    /// against our server, and parses the relayed bytes exactly the same
    /// way, because `relay_sql_batch` forwards them byte for byte.
    #[tokio::test]
    async fn proxies_a_real_query_from_a_test_client_through_our_server() {
        if !live_test_enabled() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let password = std::env::var("WARPGATE_MSSQL_TEST_SA_PASSWORD")
            .expect("WARPGATE_MSSQL_TEST_SA_PASSWORD must be set for the login test");

        let mut backend = connect().await;
        client_prelogin_handshake(&mut backend, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake with the real backend");
        client_login7_sql_auth(&mut backend, "sa", &password)
            .await
            .expect("LOGIN7 with the real backend should succeed");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut frontend, _) = listener.accept().await.expect("accept");
            server_read_prelogin(&mut frontend).await.expect("decode PreLogin");
            server_send_prelogin_response(
                &mut frontend,
                &PreLogin::new().with_encryption(EncryptionLevel::NotSupported),
            )
            .await
            .expect("send PreLogin response");
            let authenticated = server_authenticate_sql(&mut frontend, "proxyuser", "proxypass")
                .await
                .expect("authenticate");
            assert!(authenticated, "proxy-side credential check should accept its own test credentials");

            let sql = server_read_sql_batch(&mut frontend).await.expect("decode SqlBatch");
            relay_sql_batch(&mut backend, &mut frontend, &sql).await.expect("relay to the real backend");
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our proxy");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake with our proxy");
        client_login7_sql_auth(&mut client_stream, "proxyuser", "proxypass")
            .await
            .expect("LOGIN7 with our proxy should succeed");

        let result = client_sql_batch(&mut client_stream, "SELECT 1 AS n")
            .await
            .expect("SELECT 1 relayed through our proxy should succeed");

        server_task.await.expect("server task panicked");

        assert_eq!(result.column_names, vec!["n".to_string()]);
        assert_eq!(result.row_count, 1);
        assert_eq!(result.done_row_count, Some(1));
    }

    /// `run_proxy_session` end to end: a real session, not one query on an
    /// already-open connection like the test above. Two different queries
    /// over the same connection (proving the loop actually loops, not just
    /// handles one request and happens to work), then the client disconnects
    /// and the server task must return `Ok(())` — a clean hang-up between
    /// requests is the end of a session, not an error.
    #[tokio::test]
    async fn proxy_session_handles_multiple_queries_then_a_clean_disconnect() {
        if !live_test_enabled() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let password = std::env::var("WARPGATE_MSSQL_TEST_SA_PASSWORD")
            .expect("WARPGATE_MSSQL_TEST_SA_PASSWORD must be set for the login test");

        let mut backend = connect().await;
        client_prelogin_handshake(&mut backend, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake with the real backend");
        client_login7_sql_auth(&mut backend, "sa", &password)
            .await
            .expect("LOGIN7 with the real backend should succeed");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut frontend, _) = listener.accept().await.expect("accept");
            run_proxy_session(&mut frontend, &mut backend, EncryptionLevel::NotSupported, |u, p| {
                u == "proxyuser" && p == "proxypass"
            })
            .await
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our proxy");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake with our proxy");
        client_login7_sql_auth(&mut client_stream, "proxyuser", "proxypass")
            .await
            .expect("LOGIN7 with our proxy should succeed");

        let first = client_sql_batch(&mut client_stream, "SELECT 1 AS n")
            .await
            .expect("first query relayed through our proxy should succeed");
        assert_eq!(first.column_names, vec!["n".to_string()]);
        assert_eq!(first.done_row_count, Some(1));

        let second = client_sql_batch(&mut client_stream, "SELECT 2 AS m")
            .await
            .expect("second query on the same session should also succeed");
        assert_eq!(second.column_names, vec!["m".to_string()]);
        assert_eq!(second.done_row_count, Some(1));

        drop(client_stream);
        server_task
            .await
            .expect("server task panicked")
            .expect("a clean client disconnect between requests must end the session with Ok(()), not an error");
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

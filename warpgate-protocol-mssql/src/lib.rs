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

use bytes::{Bytes, BytesMut};
use tds_protocol::{
    EncryptionLevel, Login7, PacketHeader, PacketStatus, PacketType, PreLogin, Token, TokenParser,
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

#[cfg(test)]
mod tests {
    //! Needs a real SQL Server reachable at `WARPGATE_MSSQL_TEST_ADDR` (default
    //! `127.0.0.1:14330`, matching the throwaway container this crate was
    //! developed against — see `ARCHITECTURE_TECHNIQUE.md` §12). Same
    //! "needs a live server" limitation `ldap_group`'s tests already have —
    //! not run as part of the default `cross test` sweep, opt in with:
    //! `WARPGATE_MSSQL_TEST=1 cross test -p warpgate-protocol-mssql`.
    //!
    //! `WARPGATE_MSSQL_TEST_SA_PASSWORD` must match the container's
    //! `MSSQL_SA_PASSWORD` for the login tests.

    use super::*;

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

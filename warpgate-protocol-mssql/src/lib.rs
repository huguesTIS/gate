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
use tds_protocol::{PacketHeader, PacketStatus, PacketType, PreLogin, Token, TokenParser};
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

/// Sends a client PreLogin request over `stream` and returns the server's
/// decoded response. One TDS packet each way — no chunking, since a PreLogin
/// payload is always well under `DEFAULT_PACKET_SIZE`.
///
/// This is the client side of the handshake (dialing a real backend as if we
/// were the proxied client) — proves `tds-protocol`'s encode/decode against a
/// real server before any server-side (listener) code is written.
pub async fn client_prelogin_handshake(
    stream: &mut TcpStream,
) -> Result<PreLogin, MssqlError> {
    let request = PreLogin::new();
    let payload = request.encode();

    let header = PacketHeader::new(
        PacketType::PreLogin,
        PacketStatus::END_OF_MESSAGE,
        (tds_protocol::PACKET_HEADER_SIZE + payload.len()) as u16,
    );
    let mut out = BytesMut::with_capacity(header.length as usize);
    header.encode(&mut out);
    out.extend_from_slice(&payload);
    stream.write_all(&out).await?;
    stream.flush().await?;

    let mut header_buf = [0u8; tds_protocol::PACKET_HEADER_SIZE];
    stream.read_exact(&mut header_buf).await?;
    let response_header = PacketHeader::decode(&mut &header_buf[..])?;

    let body_len = response_header.length as usize - tds_protocol::PACKET_HEADER_SIZE;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;

    // Real SQL Server labels its PreLogin *response* with the TabularResult
    // packet type (0x04), not PreLogin (0x12) — confirmed against a live
    // SQL Server 2022 container: the body decodes cleanly as a PreLogin
    // response (product version, encryption, MARS) even though the header
    // says TabularResult. MS-TDS itself doesn't document this distinctly
    // from a real query-result/error stream; a client is expected to know
    // from protocol state (it just sent PreLogin) which one it's reading.
    // Anything else genuinely is unexpected and gets the token-stream error
    // decoded for diagnostics.
    if !matches!(response_header.packet_type, PacketType::PreLogin | PacketType::TabularResult) {
        let detail = describe_unexpected_packet(Bytes::from(body));
        return Err(MssqlError::UnexpectedPacketType(
            response_header.packet_type,
            detail,
        ));
    }

    Ok(PreLogin::decode(body.as_slice())?)
}

#[cfg(test)]
mod tests {
    //! Needs a real SQL Server reachable at `WARPGATE_MSSQL_TEST_ADDR` (default
    //! `127.0.0.1:14330`, matching the throwaway container this crate was
    //! developed against — see `ARCHITECTURE_TECHNIQUE.md` §07). Same
    //! "needs a live server" limitation `ldap_group`'s tests already have —
    //! not run as part of the default `cross test` sweep, opt in with:
    //! `WARPGATE_MSSQL_TEST=1 cross test -p warpgate-protocol-mssql`.

    use super::*;

    #[tokio::test]
    async fn completes_prelogin_against_a_real_sql_server() {
        if std::env::var("WARPGATE_MSSQL_TEST").is_err() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let addr = std::env::var("WARPGATE_MSSQL_TEST_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:14330".to_string());
        let mut stream = TcpStream::connect(&addr)
            .await
            .unwrap_or_else(|e| panic!("connect to {addr}: {e}"));

        let response = client_prelogin_handshake(&mut stream)
            .await
            .expect("PreLogin handshake");

        assert!(
            response.server_version.is_some(),
            "a real SQL Server must report its product version in PreLogin"
        );
    }
}

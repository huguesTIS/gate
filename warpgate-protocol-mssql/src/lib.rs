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
//! Wired into the `warpgate` binary as of 23 Aug 2026 — `MssqlProtocolServer`
//! (this file) implements `warpgate-core`'s `ProtocolServer`, and
//! `session::MssqlSession` implements `DbAuthTransport`, the same two traits
//! `warpgate-protocol-mysql`/`warpgate-protocol-postgres` already implement,
//! so an MSSQL target goes through the exact same governed auth flow
//! (`run_db_authorization`) as those two — JIT grants, RBAC, audit trail,
//! brute-force lockout, not just a working proxy. The low-level protocol
//! functions below (PreLogin/LOGIN7, TLS-in-TDS, generic relay, typed row
//! decoding) were proven out first against a real Dockerized SQL Server,
//! deliberately free of warpgate-core so iteration on them stayed fast; that
//! isolation is gone now that this crate depends on it like every other
//! protocol crate, but `examples/proxy_server.rs` still works unchanged for
//! quick wire-level iteration without a full `warpgate` build.
//!
//! Every function below that touches the wire is generic over
//! `impl AsyncRead + AsyncWrite + Unpin` rather than hardcoded to
//! `TcpStream` — the point being TLS-in-TDS (see [`client_upgrade_to_tls`]):
//! a `TlsStream<TlsPreloginWrapper<TcpStream>>` satisfies the same bound, so
//! `client_login7_sql_auth`/`client_sql_batch`/`run_proxy_session`/etc. work
//! unchanged over an encrypted connection, no separate encrypted-path copies
//! of any of this logic needed.

mod client;
mod login7_decode;
mod server_tokens;
mod session;
mod session_handle;

use std::sync::Arc;

use anyhow::Context;
use bytes::{Buf, Bytes, BytesMut};
use futures::FutureExt;
use futures::future::BoxFuture;
pub use login7_decode::decode_login7;
use mssql_tls::{TlsConfig, TlsConnector, TlsPreloginWrapper};
pub use server_tokens::{build_login_failure_response, build_login_success_response};
// Re-exported: these appear directly in this crate's own public function
// signatures (EncryptionLevel/PreLogin as parameters and return types,
// Login7 as server_read_login7's return type), so a caller needs to name
// them without also taking a direct dependency on tds-protocol itself.
pub use tds_protocol::{EncryptionLevel, Login7, PreLogin};
use tds_protocol::{
    ColMetaData, ColumnData, NbcRow, PacketStatus, PacketType, RawRow, SqlBatch, Token,
    TokenParser, TypeId,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{Instrument, error, info, warn};
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::accept_loop;
use warpgate_core::{ProtocolServer, Services, SessionStateInit, State};
use warpgate_tls::{ResolveServerCert, TlsCertificateAndPrivateKey};

use crate::session::MssqlSession;
use crate::session_handle::MssqlSessionHandle;

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
    #[error("malformed row data: {0}")]
    MalformedRow(String),
    #[error(transparent)]
    Warpgate(#[from] warpgate_common::WarpgateError),
    #[error("{0} authentication is not yet supported for MSSQL targets")]
    TargetAuthNotSupported(&'static str),
}

/// One decoded column value from a `Row`/`NbcRow` token. Covers numerics,
/// strings, exact decimals, dates/times, and GUIDs; anything still not
/// interpreted (legacy single-byte `CHAR`/`VARCHAR`/`TEXT` — needs the
/// column's collation to pick a codepage, which this crate doesn't track —
/// plus genuine binary data: `BINARY`/`VARBINARY`/`XML`/`UDT`) comes back as
/// `Bytes`, the type's own wire-encoded value bytes, not dropped, just not
/// further interpreted. See [`decode_one_column_value`] for exactly what's
/// covered and the wire-format math behind `Decimal`/`DateTime`/`Guid`.
#[derive(Debug, Clone, PartialEq)]
pub enum ColumnValue {
    Null,
    Bit(bool),
    /// Unifies `TINYINT`/`SMALLINT`/`INT`/`BIGINT` (and their nullable `*N`
    /// wire forms) into one width, same as most higher-level driver APIs do.
    Int(i64),
    /// Unifies `REAL`(`FLOAT4`)/`FLOAT`(`FLOAT8`).
    Float(f64),
    /// `NVARCHAR`/`NCHAR`/`NTEXT` (native UTF-16LE, decoded losslessly) —
    /// legacy single-byte `CHAR`/`VARCHAR`/`TEXT` are `Bytes` instead, since
    /// decoding those correctly needs the column's collation (which
    /// selects the codepage) and this crate doesn't track collation.
    Text(String),
    /// `DECIMAL`/`NUMERIC`/`MONEY`/`SMALLMONEY`, formatted as exact
    /// fixed-point text (e.g. `"1.23"`, `"-0.0400"`) computed via
    /// big-integer arithmetic on the wire mantissa — never rounded through
    /// a float, unlike [`ColumnValue::Float`].
    Decimal(String),
    /// `UNIQUEIDENTIFIER`, formatted as standard
    /// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` text.
    Guid(String),
    /// `DATE`/`TIME`/`DATETIME2`/`DATETIMEOFFSET`/`DATETIME`/
    /// `SMALLDATETIME`, formatted as ISO-8601-ish text: `"YYYY-MM-DD"`
    /// (`Date` alone), `"HH:MM:SS[.fffffff]"` (`Time` alone), or
    /// `"YYYY-MM-DD HH:MM:SS[.fffffff][ ±HH:MM]"` for the combined forms.
    DateTime(String),
    Bytes(Bytes),
}

/// Result of a `SqlBatch`/RPC call: the `SqlBatch` → `ColMetaData` →
/// `Row`/`NbcRow` → `Done` token sequence, with each row decoded into
/// [`ColumnValue`]s via [`decode_one_column_value`] rather than left as
/// `RawRow`'s undecoded wire bytes (`tds-protocol` is explicit that
/// per-type decoding is the caller's job — see that function's doc comment
/// for what's covered).
#[derive(Debug)]
pub struct QueryResult {
    pub column_names: Vec<String>,
    pub row_count: usize,
    /// Rows actually affected/returned, per the server's own `DONE` token —
    /// compared against `row_count` (rows this crate actually saw) as a
    /// consistency check, not just trusted blindly.
    pub done_row_count: Option<u64>,
    pub rows: Vec<Vec<ColumnValue>>,
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
    write_tds_message_with_status(
        stream,
        packet_type,
        PacketStatus::END_OF_MESSAGE.bits(),
        payload,
    )
    .await
}

/// Same as [`write_tds_message`], but with an explicit raw status byte
/// instead of always `END_OF_MESSAGE` — used when relaying a client's own
/// request to the backend, so bits the client actually set (e.g.
/// `RESET_CONNECTION`, used by ADO.NET connection pooling — a real SSMS/
/// `Microsoft.Data.SqlClient` pooled connection sends this) survive the
/// relay instead of being silently collapsed to a plain end-of-message.
///
/// Chunks `payload` into packets no larger than [`MAX_TDS_PACKET_SIZE`]
/// (matching the `4096` we advertise via `EnvChange(PacketSize)` in the
/// relayed LOGIN7 response — see `build_login_success_response`'s replacement
/// in `run_proxy_session`). A large multi-packet client request (observed
/// live: SSMS's Object Explorer sends an 8+KB `SqlBatch` enumerating server
/// objects) gets fully reassembled by [`read_tds_message`] before reaching
/// here — writing that back out as a single oversized physical packet
/// violates the packet size the backend was told to expect, and a real SQL
/// Server just stops responding rather than erroring (observed live: the
/// proxy session hung forever on the very first large query, no error
/// logged on either side). Every chunk but the last carries `status` with
/// `END_OF_MESSAGE` cleared (but any other bit, e.g. `RESET_CONNECTION`,
/// preserved — real clients set those on every packet of a fragmented
/// message, not just the last); only the last chunk gets `status` as given
/// (already `END_OF_MESSAGE`-set, since it's what [`read_tds_message`]
/// captured from the packet that terminated the message).
async fn write_tds_message_with_status(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    packet_type: PacketType,
    status: u8,
    payload: &[u8],
) -> Result<(), MssqlError> {
    let eom_bit = PacketStatus::END_OF_MESSAGE.bits();
    let non_eom_status = status & !eom_bit;

    if payload.is_empty() {
        return write_one_tds_packet(stream, packet_type, status, payload).await;
    }

    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + MAX_TDS_PACKET_BODY_SIZE).min(payload.len());
        let is_last_chunk = end == payload.len();
        let chunk_status = if is_last_chunk { status } else { non_eom_status };
        write_one_tds_packet(stream, packet_type, chunk_status, &payload[offset..end]).await?;
        offset = end;
    }
    Ok(())
}

/// The packet size this crate advertises via `EnvChange(PacketSize)` in
/// LOGIN7 responses and assumes when chunking outgoing messages — see
/// [`write_tds_message_with_status`].
const MAX_TDS_PACKET_SIZE: usize = 4096;
const MAX_TDS_PACKET_BODY_SIZE: usize = MAX_TDS_PACKET_SIZE - tds_protocol::PACKET_HEADER_SIZE;

/// Writes exactly one physical TDS packet (header + `payload`, `payload`
/// already assumed to fit) — the primitive [`write_tds_message_with_status`]
/// chunks large messages into. Written by hand rather than through
/// `tds_protocol::PacketHeader` (`PacketStatus::from_bits` rejects any
/// status byte not covered by its own flag set, and a real client can send
/// bits outside it — see [`read_tds_message`]).
async fn write_one_tds_packet(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    packet_type: PacketType,
    status: u8,
    payload: &[u8],
) -> Result<(), MssqlError> {
    let length = (tds_protocol::PACKET_HEADER_SIZE + payload.len()) as u16;
    let header = [
        packet_type as u8,
        status,
        (length >> 8) as u8,
        length as u8,
        0, // spid (high byte)
        0, // spid (low byte)
        0, // packet_id
        0, // window
    ];
    let mut out = BytesMut::with_capacity(header.len() + payload.len());
    out.extend_from_slice(&header);
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
///
/// Also returns the raw status byte of the terminating packet. Header
/// parsing here deliberately does **not** go through
/// `tds_protocol::PacketHeader::decode` — its `PacketStatus::from_bits`
/// rejects any status byte outside `NORMAL`/`END_OF_MESSAGE`/`IGNORE_EVENT`/
/// `RESET_CONNECTION`/`RESET_CONNECTION_KEEP_TRANSACTION`, but a real client
/// sends other bits it doesn't cover: SSMS's `Microsoft.Data.SqlClient`
/// pooled connections were observed sending status `0x04`, which crashed the
/// proxy with `InvalidPacketStatus` on the very first request after a
/// successful login. This crate is a byte relay, not a full TDS
/// implementation — it only needs the packet type and the end-of-message bit
/// (checked directly), not a fully-interpreted status; the raw byte is
/// threaded back to the caller so [`relay_one_message`] can forward it
/// unchanged rather than silently dropping bits like `RESET_CONNECTION`.
async fn read_tds_message(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<(PacketType, u8, Bytes), MssqlError> {
    let mut full_body = BytesMut::new();
    let mut packet_type = None;
    let mut last_status;
    loop {
        let mut header_buf = [0u8; tds_protocol::PACKET_HEADER_SIZE];
        stream.read_exact(&mut header_buf).await?;

        let pt = PacketType::from_u8(header_buf[0])?;
        let status_byte = header_buf[1];
        let length = u16::from_be_bytes([header_buf[2], header_buf[3]]) as usize;

        if packet_type.is_none() {
            packet_type = Some(pt);
        }
        last_status = status_byte;

        let body_len = length.saturating_sub(tds_protocol::PACKET_HEADER_SIZE);
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).await?;
        full_body.extend_from_slice(&body);

        if status_byte & PacketStatus::END_OF_MESSAGE.bits() != 0 {
            break;
        }
    }
    // A packet_type is always set: the loop above always executes at least
    // once before it can break, so this only fails to unwrap if the server
    // sends zero packets — which read_exact would already have errored on.
    Ok((
        packet_type.unwrap_or(PacketType::TabularResult),
        last_status,
        full_body.freeze(),
    ))
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

    let (packet_type, _status, body) = read_tds_message(stream).await?;

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

/// A client-side stream that may or may not have been upgraded to TLS during
/// PreLogin — the dial-side counterpart to [`MaybeTlsStream`], for a caller
/// (like `warpgate-protocol-mssql`'s own target-dialing code) that decides
/// whether to call [`client_upgrade_to_tls`] based on the *target's* TLS
/// policy and the real server's PreLogin response, and needs one concrete
/// type afterward regardless of which way that went. Implements
/// `AsyncRead + AsyncWrite` by delegating to whichever variant is present.
pub enum MaybeTlsClientStream<S> {
    Plain(S),
    /// Boxed for the same reason as [`MaybeTlsStream::Tls`] — `TlsStream` is
    /// large relative to a bare socket.
    Tls(Box<mssql_tls::TlsStream<TlsPreloginWrapper<S>>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTlsClientStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsClientStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            MaybeTlsClientStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTlsClientStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsClientStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            MaybeTlsClientStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsClientStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            MaybeTlsClientStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsClientStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            MaybeTlsClientStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Reads and decodes a client's PreLogin request. Server-side counterpart to
/// [`client_prelogin_handshake`]'s outbound half — the first piece of the
/// *listener* side of the protocol (accepting a connection), as opposed to
/// every function above, which dials one. `tds-protocol`'s `PreLogin::decode`
/// is direction-agnostic (used here for the request, above for the response),
/// so no new wire-format code was needed for this half — unlike LOGIN7 below.
pub async fn server_read_prelogin(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<PreLogin, MssqlError> {
    let (packet_type, _status, body) = read_tds_message(stream).await?;
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
    let (packet_type, _status, body) = read_tds_message(stream).await?;
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
///
/// Returns the raw response body on success (everything after LOGINACK —
/// real SQL Server also sends `EnvChange(Database)`/`EnvChange(SqlCollation)`/
/// `EnvChange(PacketSize)`/`Info`/`Done` alongside it, not just LOGINACK
/// itself). [`run_proxy_session`] relays these bytes to the frontend verbatim
/// instead of synthesizing its own response — a hand-built LOGINACK alone
/// (no collation/database negotiation) is what a real client like SSMS's
/// `Microsoft.Data.SqlClient` rejects as an invalid protocol negotiation; see
/// `ARCHITECTURE_TECHNIQUE.md` §12 for the full writeup.
pub async fn client_login7_sql_auth(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    username: &str,
    password: &str,
) -> Result<Bytes, MssqlError> {
    let login = Login7::new().with_sql_auth(username, password);
    let payload = login.encode();
    write_tds_message(stream, PacketType::Tds7Login, &payload).await?;

    let (packet_type, _status, body) = read_tds_message(stream).await?;
    if packet_type != PacketType::TabularResult {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a TabularResult LOGIN7 response".to_string(),
        ));
    }

    let mut parser = TokenParser::new(body.clone());
    while let Some(token) = parser.next_token()? {
        match token {
            Token::Error(err) => {
                return Err(MssqlError::LoginRejected(format!(
                    "{} (state {}): {}",
                    err.number, err.state, err.message
                )));
            }
            Token::LoginAck(_) => return Ok(body),
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
pub async fn client_sql_batch(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    sql: &str,
) -> Result<QueryResult, MssqlError> {
    let payload = SqlBatch::new(sql).encode();
    write_tds_message(stream, PacketType::SqlBatch, &payload).await?;

    let (packet_type, _status, body) = read_tds_message(stream).await?;
    if packet_type != PacketType::TabularResult {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a TabularResult SqlBatch response".to_string(),
        ));
    }
    parse_query_result(body)
}

/// Sends `request` as an RPC packet — a stored procedure call, or (via
/// [`tds_protocol::RpcRequest::execute_sql`]) `sp_executesql`, the way real
/// drivers actually run parameterized queries (as opposed to a `SqlBatch`
/// containing literal `EXEC ...` text, which also works but isn't what a
/// real client sends). **Must** be called after a successful
/// [`client_login7_sql_auth`] on the same connection.
pub async fn client_rpc_call(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    request: &tds_protocol::RpcRequest,
) -> Result<QueryResult, MssqlError> {
    let payload = request.encode();
    write_tds_message(stream, PacketType::Rpc, &payload).await?;

    let (packet_type, _status, body) = read_tds_message(stream).await?;
    if packet_type != PacketType::TabularResult {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a TabularResult RPC response".to_string(),
        ));
    }
    parse_query_result(body)
}

/// Shared token-parsing loop behind [`client_sql_batch`] and
/// [`client_rpc_call`]. Both answer with the same `ColMetaData`/`Row`/
/// `NbcRow` token shape, but *not* the same completion token: a plain
/// `SqlBatch` SELECT ends in `Done`, while an RPC call (`sp_executesql`
/// included) wraps the inner statement's completion in `DoneInProc` and
/// only emits the outer `Done`/`DoneProc` for the whole call — found the
/// hard way, `done_row_count` came back `None` against a real RPC response
/// until `DoneProc`/`DoneInProc` were handled too, even though the row
/// count was genuinely there, just on a different token type.
fn parse_query_result(body: Bytes) -> Result<QueryResult, MssqlError> {
    let mut parser = TokenParser::new(body);
    let mut metadata: Option<ColMetaData> = None;
    let mut column_names = Vec::new();
    let mut row_count = 0usize;
    let mut done_row_count = None;
    let mut rows = Vec::new();

    while let Some(token) = parser.next_token_with_metadata(metadata.as_ref())? {
        match token {
            Token::ColMetaData(md) => {
                column_names = md.columns.iter().map(|c| c.name.clone()).collect();
                metadata = Some(md);
            }
            Token::Row(row) => {
                row_count += 1;
                let columns = &metadata
                    .as_ref()
                    .ok_or_else(|| MssqlError::MalformedRow("ROW token before ColMetaData".to_string()))?
                    .columns;
                rows.push(decode_raw_row(&row, columns)?);
            }
            Token::NbcRow(row) => {
                row_count += 1;
                let columns = &metadata
                    .as_ref()
                    .ok_or_else(|| MssqlError::MalformedRow("NBCROW token before ColMetaData".to_string()))?
                    .columns;
                rows.push(decode_nbc_row(&row, columns)?);
            }
            Token::Done(done) if done.status.count => done_row_count = Some(done.row_count),
            Token::DoneProc(done) if done.status.count => done_row_count = Some(done.row_count),
            Token::DoneInProc(done) if done.status.count => done_row_count = Some(done.row_count),
            Token::Error(err) => {
                return Err(MssqlError::QueryFailed(format!(
                    "{} (state {}): {}",
                    err.number, err.state, err.message
                )));
            }
            _ => {}
        }
    }

    Ok(QueryResult { column_names, row_count, done_row_count, rows })
}

/// Decodes every column of a `RawRow` (every column present, including
/// nulls, marked via each type's own length-prefix sentinel) into
/// [`ColumnValue`]s — see [`decode_one_column_value`].
fn decode_raw_row(row: &RawRow, columns: &[ColumnData]) -> Result<Vec<ColumnValue>, MssqlError> {
    let mut cursor: &[u8] = &row.data;
    columns.iter().map(|col| decode_one_column_value(&mut cursor, col)).collect()
}

/// Decodes every column of an `NbcRow` (null columns carry zero bytes —
/// skipped per `row.null_bitmap` — rather than a per-type null sentinel;
/// only non-null columns are read from `row.data`) into [`ColumnValue`]s —
/// see [`decode_one_column_value`].
fn decode_nbc_row(row: &NbcRow, columns: &[ColumnData]) -> Result<Vec<ColumnValue>, MssqlError> {
    let mut cursor: &[u8] = &row.data;
    columns
        .iter()
        .enumerate()
        .map(|(i, col)| {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let is_null = row
                .null_bitmap
                .get(byte_idx)
                .is_some_and(|b| b & (1 << bit_idx) != 0);
            if is_null {
                Ok(ColumnValue::Null)
            } else {
                decode_one_column_value(&mut cursor, col)
            }
        })
        .collect()
}

/// Reads a 1-byte length-prefixed value (`0x00` = NULL) — the wire format
/// `tds-protocol`'s own `RawRow::decode_column_value` (private, mirrored
/// here) re-serializes into `RawRow`/`NbcRow`'s `data` for
/// `IntN`/`BitN`/`FloatN`/`MoneyN`/`DateTimeN`/`Guid`/`Decimal`/`Numeric`/
/// `DecimalN`/`NumericN`/`Char`/`VarChar`/`Binary`/`VarBinary`/`Date`/
/// `Time`/`DateTime2`/`DateTimeOffset`.
///
/// **`0x00`, not `0xFF`, is NULL here** — found the hard way against a real
/// server: `tds-protocol`'s own (private) `decode_bytelen_type` comments a
/// length byte of `0xFF` as "NULL value" and `0` as merely "Empty value",
/// but a genuine `CAST(NULL AS INT)` column from a live SQL Server sent a
/// length byte of `0`, not `0xFF` — confirmed by
/// `decodes_typed_column_values_from_a_real_select` failing with
/// `"unexpected IntN width 0"` before this was fixed. The fixed-width
/// numeric/date/GUID types this reader mostly serves have no meaningful
/// "present but zero-length" value distinct from NULL, so this loses
/// nothing for them; `Char`/`VarChar`/`Binary`/`VarBinary` genuinely can be
/// an empty-but-non-null value, which this now can't distinguish from NULL
/// — an acceptable gap since this crate only returns those as
/// `ColumnValue::Bytes` (not a typed value) anyway. `0xFF` (255) as an
/// actual length is treated as a real 255-byte value like any other, not
/// specially — untested against a real server either way, but consistent
/// with everything else this reader does.
fn read_bytelen_prefixed(cursor: &mut &[u8]) -> Result<Option<Bytes>, MssqlError> {
    if cursor.remaining() < 1 {
        return Err(MssqlError::MalformedRow("unexpected end of row data".to_string()));
    }
    let len = cursor.get_u8();
    if len == 0 {
        return Ok(None);
    }
    let len = len as usize;
    if cursor.remaining() < len {
        return Err(MssqlError::MalformedRow("unexpected end of row data".to_string()));
    }
    Ok(Some(cursor.copy_to_bytes(len)))
}

/// Same as [`read_bytelen_prefixed`], but with a 2-byte length prefix
/// (`0xFFFF` = NULL) — used for `NVarChar`/`NChar`/`BigChar`/`BigBinary` and
/// non-`MAX` `BigVarChar`/`BigVarBinary`.
fn read_ushortlen_prefixed(cursor: &mut &[u8]) -> Result<Option<Bytes>, MssqlError> {
    if cursor.remaining() < 2 {
        return Err(MssqlError::MalformedRow("unexpected end of row data".to_string()));
    }
    let len = cursor.get_u16_le();
    if len == 0xFFFF {
        return Ok(None);
    }
    let len = len as usize;
    if cursor.remaining() < len {
        return Err(MssqlError::MalformedRow("unexpected end of row data".to_string()));
    }
    Ok(Some(cursor.copy_to_bytes(len)))
}

/// Same as [`read_bytelen_prefixed`], but with a 4-byte length prefix
/// (`0xFFFFFFFF` = NULL) — used for `Variant`.
fn read_intlen_prefixed(cursor: &mut &[u8]) -> Result<Option<Bytes>, MssqlError> {
    if cursor.remaining() < 4 {
        return Err(MssqlError::MalformedRow("unexpected end of row data".to_string()));
    }
    let len = cursor.get_u32_le();
    if len == 0xFFFF_FFFF {
        return Ok(None);
    }
    let len = len as usize;
    if cursor.remaining() < len {
        return Err(MssqlError::MalformedRow("unexpected end of row data".to_string()));
    }
    Ok(Some(cursor.copy_to_bytes(len)))
}

/// Reads a PLP (Partially Length-Prefixed) value: 8-byte total length
/// (`u64::MAX` = NULL) followed by `(4-byte chunk length, chunk data)*`
/// terminated by a zero-length chunk. Used for `MAX`-length
/// `NVarChar`/`BigVarChar`/`BigVarBinary`, `Xml`, `Udt` — and, since
/// `tds-protocol`'s `RawRow::decode_column_value` re-encodes them this way
/// rather than preserving the wire `textptr` layout (see its doc comment),
/// also `Text`/`NText`/`Image`.
fn read_plp_bytes(cursor: &mut &[u8]) -> Result<Option<Bytes>, MssqlError> {
    let eof = || MssqlError::MalformedRow("unexpected end of row data".to_string());
    if cursor.remaining() < 8 {
        return Err(eof());
    }
    let total_len = cursor.get_u64_le();
    if total_len == u64::MAX {
        return Ok(None);
    }
    let mut out = BytesMut::new();
    loop {
        if cursor.remaining() < 4 {
            return Err(eof());
        }
        let chunk_len = cursor.get_u32_le() as usize;
        if chunk_len == 0 {
            break;
        }
        if cursor.remaining() < chunk_len {
            return Err(eof());
        }
        out.extend_from_slice(&cursor.copy_to_bytes(chunk_len));
    }
    Ok(Some(out.freeze()))
}

/// Decodes UTF-16LE bytes losslessly (invalid surrogate pairs become
/// U+FFFD), matching `tds-protocol`'s own `read_utf16_string` convention.
fn utf16le_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// `col.type_info.scale` isn't set for every type — required for
/// `DECIMAL`/`NUMERIC`/`TIME`/`DATETIME2`/`DATETIMEOFFSET`, where it's what
/// tells us the tick multiplier / decimal point position, not optional
/// metadata this crate can fall back on a default for.
fn column_scale(col: &ColumnData) -> Result<u8, MssqlError> {
    col.type_info
        .scale
        .ok_or_else(|| MssqlError::MalformedRow(format!("{:?} column has no scale in its metadata", col.type_id)))
}

/// Reads up to 8 bytes as a little-endian unsigned integer — the generic
/// primitive behind the various fixed-width tick/day/minute counters below
/// (`TIME`'s scale-dependent width, `DATE`'s 3 bytes, etc.), all of which
/// are narrower than a `u64` but not a fixed width across types.
fn read_le_uint(bytes: &[u8]) -> Result<u64, MssqlError> {
    if bytes.len() > 8 {
        return Err(MssqlError::MalformedRow(format!("integer field too wide: {} bytes", bytes.len())));
    }
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

/// Formats an unsigned integer mantissa with an implied decimal point
/// `scale` digits from the right, as exact text (e.g. mantissa `123`, scale
/// `2` → `"1.23"`) — the shared primitive behind `DECIMAL`/`NUMERIC`/
/// `MONEY`/`SMALLMONEY`, all of which are just a scaled integer on the
/// wire. Operates on the mantissa's decimal digit string rather than
/// dividing as a float, so it stays exact even at `DECIMAL`'s full 38-digit
/// precision (a `u128` comfortably holds that: `2^128 ≈ 3.4×10^38` versus a
/// max mantissa of `10^38 - 1`).
fn format_fixed_point(mantissa: u128, scale: u8, positive: bool) -> String {
    let digits = mantissa.to_string();
    let scale = scale as usize;
    let mut s = String::new();
    if !positive && mantissa != 0 {
        s.push('-');
    }
    if scale == 0 {
        s.push_str(&digits);
    } else if digits.len() > scale {
        let split = digits.len() - scale;
        s.push_str(&digits[..split]);
        s.push('.');
        s.push_str(&digits[split..]);
    } else {
        s.push_str("0.");
        for _ in 0..(scale - digits.len()) {
            s.push('0');
        }
        s.push_str(&digits);
    }
    s
}

/// Decodes `DECIMAL`/`NUMERIC`'s wire format: a 1-byte sign (`1` = positive,
/// `0` = negative — confirmed against a real server; unlike the length
/// byte's NULL sentinel, this one wasn't a surprise) followed by the
/// mantissa as a little-endian unsigned integer of variable width (4, 8,
/// 12, or 16 bytes depending on precision).
fn format_decimal(bytes: &[u8], scale: u8) -> Result<String, MssqlError> {
    let Some((&sign_byte, mantissa_bytes)) = bytes.split_first() else {
        return Err(MssqlError::MalformedRow("empty DECIMAL/NUMERIC value".to_string()));
    };
    if mantissa_bytes.len() > 16 {
        return Err(MssqlError::MalformedRow(format!(
            "DECIMAL/NUMERIC mantissa too wide: {} bytes",
            mantissa_bytes.len()
        )));
    }
    let mut buf = [0u8; 16];
    buf[..mantissa_bytes.len()].copy_from_slice(mantissa_bytes);
    Ok(format_fixed_point(u128::from_le_bytes(buf), scale, sign_byte != 0))
}

/// Decodes `MONEY`'s wire format: two little-endian `u32` halves (high,
/// then low) forming a 64-bit signed integer scaled by `10^4` (see
/// `TypeId::Money`'s arm in `decode_one_column_value` — `RawRow` stores
/// these two halves back-to-back verbatim, not pre-combined).
fn format_money(bytes: &[u8]) -> Result<String, MssqlError> {
    if bytes.len() != 8 {
        return Err(MssqlError::MalformedRow(format!("MONEY must be 8 bytes, got {}", bytes.len())));
    }
    let hi = i32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let lo = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let combined = (i64::from(hi) << 32) | i64::from(lo);
    Ok(format_fixed_point(combined.unsigned_abs() as u128, 4, combined >= 0))
}

/// Decodes `SMALLMONEY`'s wire format: one little-endian signed `i32`
/// scaled by `10^4`.
fn format_money4(bytes: &[u8]) -> Result<String, MssqlError> {
    if bytes.len() != 4 {
        return Err(MssqlError::MalformedRow(format!("SMALLMONEY must be 4 bytes, got {}", bytes.len())));
    }
    let v = i32::from_le_bytes(bytes.try_into().unwrap());
    Ok(format_fixed_point(v.unsigned_abs() as u128, 4, v >= 0))
}

/// Formats a 16-byte `UNIQUEIDENTIFIER` as standard GUID text. TDS's wire
/// layout is Microsoft's mixed-endian GUID format: the first three fields
/// (4+2+2 bytes) are little-endian, the last 8 bytes are used as-is.
fn format_guid(bytes: &[u8]) -> Result<String, MssqlError> {
    if bytes.len() != 16 {
        return Err(MssqlError::MalformedRow(format!("GUID must be 16 bytes, got {}", bytes.len())));
    }
    let data1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let data2 = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    let data3 = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
    let d4 = &bytes[8..16];
    Ok(format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    ))
}

/// Howard Hinnant's `civil_from_days` algorithm (public domain,
/// http://howardhinnant.github.io/date_algorithms.html): converts a day
/// count relative to the Unix epoch (1970-01-01, may be negative) into a
/// proleptic-Gregorian `(year, month, day)`. The shared primitive behind
/// every date/datetime format function below — each just computes the
/// right day-count offset for its own epoch and calls this.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097); // true floor division — handles z < 0 correctly on its own
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Number of days from `0001-01-01` (SQL Server `DATE`'s epoch) to
/// `1970-01-01` (`civil_from_days`'s epoch) — verified against .NET's
/// well-known `DateTime` epoch offset (`621355968000000000` 100ns ticks
/// from `0001-01-01` to `1970-01-01`, i.e. exactly 719162 days).
const DAYS_0001_01_01_TO_1970_01_01: i64 = 719_162;

/// Number of days from `1900-01-01` (`DATETIME`/`SMALLDATETIME`'s epoch) to
/// `1970-01-01`: 70 years, 17 of them leap (1904..=1968 step 4 — 1900
/// itself isn't a leap year, divisible by 100 but not 400) = 70×365+17.
const DAYS_1900_01_01_TO_1970_01_01: i64 = 25_567;

/// Decodes `DATE`'s wire format: an unsigned 24-bit little-endian day count
/// since `0001-01-01`.
fn format_date(bytes: &[u8]) -> Result<String, MssqlError> {
    if bytes.len() != 3 {
        return Err(MssqlError::MalformedRow(format!("DATE must be 3 bytes, got {}", bytes.len())));
    }
    let days = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
    let (y, m, d) = civil_from_days(i64::from(days) - DAYS_0001_01_01_TO_1970_01_01);
    Ok(format!("{y:04}-{m:02}-{d:02}"))
}

/// `TIME(scale)`'s wire width: 3 bytes for scale 0-2, 4 for 3-4, 5 for 5-7
/// (more fractional-second precision needs more bits) — also the width of
/// the time portion of `DATETIME2`/`DATETIMEOFFSET`, which embed the same
/// encoding.
fn time_byte_len(scale: u8) -> usize {
    match scale {
        0..=2 => 3,
        3..=4 => 4,
        _ => 5,
    }
}

/// Decodes `TIME(scale)`'s wire format: an unsigned little-endian integer
/// (width per [`time_byte_len`]) counting units of `10^-scale` seconds
/// since midnight. Scaled up to 100ns ticks internally so the output
/// always has full precision regardless of `scale`.
fn format_time(bytes: &[u8], scale: u8) -> Result<String, MssqlError> {
    if bytes.len() != time_byte_len(scale) {
        return Err(MssqlError::MalformedRow(format!(
            "TIME(scale={scale}) must be {} bytes, got {}",
            time_byte_len(scale),
            bytes.len()
        )));
    }
    let value = read_le_uint(bytes)?;
    let hundred_ns = value * 10u64.pow(u32::from(7 - scale));
    let total_seconds = hundred_ns / 10_000_000;
    let fraction = hundred_ns % 10_000_000;
    let (h, m, s) = (total_seconds / 3600, (total_seconds % 3600) / 60, total_seconds % 60);
    if fraction == 0 {
        Ok(format!("{h:02}:{m:02}:{s:02}"))
    } else {
        Ok(format!("{h:02}:{m:02}:{s:02}.{fraction:07}"))
    }
}

/// Decodes `DATETIME2(scale)`'s wire format: a `TIME(scale)` part
/// immediately followed by a 3-byte `DATE` part.
fn format_datetime2(bytes: &[u8], scale: u8) -> Result<String, MssqlError> {
    let time_len = time_byte_len(scale);
    if bytes.len() != time_len + 3 {
        return Err(MssqlError::MalformedRow(format!(
            "DATETIME2(scale={scale}) must be {} bytes, got {}",
            time_len + 3,
            bytes.len()
        )));
    }
    Ok(format!("{} {}", format_date(&bytes[time_len..])?, format_time(&bytes[..time_len], scale)?))
}

/// Decodes `DATETIMEOFFSET(scale)`'s wire format: a `DATETIME2(scale)` part
/// (time then date, same as above) followed by a 2-byte signed
/// little-endian offset in minutes from UTC.
fn format_datetimeoffset(bytes: &[u8], scale: u8) -> Result<String, MssqlError> {
    let time_len = time_byte_len(scale);
    let expected = time_len + 3 + 2;
    if bytes.len() != expected {
        return Err(MssqlError::MalformedRow(format!(
            "DATETIMEOFFSET(scale={scale}) must be {expected} bytes, got {}",
            bytes.len()
        )));
    }
    let datetime = format_datetime2(&bytes[..time_len + 3], scale)?;
    let offset_minutes = i16::from_le_bytes(bytes[time_len + 3..expected].try_into().unwrap());
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let abs = offset_minutes.unsigned_abs();
    Ok(format!("{datetime} {sign}{:02}:{:02}", abs / 60, abs % 60))
}

/// Decodes the legacy `DATETIME`'s wire format: a signed 32-bit little-endian
/// day count since `1900-01-01`, followed by an unsigned 32-bit
/// little-endian tick count since midnight, where each tick is `1/300`
/// second (SQL Server's `DATETIME` has ~3.33ms resolution, rounded to
/// `.000`/`.003`/`.007` in its own textual rendering — this formats the
/// exact millisecond value instead of replicating that rounding quirk).
fn format_old_datetime(bytes: &[u8]) -> Result<String, MssqlError> {
    if bytes.len() != 8 {
        return Err(MssqlError::MalformedRow(format!("DATETIME must be 8 bytes, got {}", bytes.len())));
    }
    let days = i32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let ticks = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let (y, m, d) = civil_from_days(i64::from(days) - DAYS_1900_01_01_TO_1970_01_01);
    let total_ms = u64::from(ticks) * 10 / 3;
    let (total_seconds, ms) = (total_ms / 1000, total_ms % 1000);
    let (h, min, s) = (total_seconds / 3600, (total_seconds % 3600) / 60, total_seconds % 60);
    Ok(format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}.{ms:03}"))
}

/// Decodes the legacy `SMALLDATETIME`'s wire format: an unsigned 16-bit
/// little-endian day count since `1900-01-01`, followed by an unsigned
/// 16-bit little-endian minute count since midnight (no seconds — this
/// type's resolution is whole minutes).
fn format_small_datetime(bytes: &[u8]) -> Result<String, MssqlError> {
    if bytes.len() != 4 {
        return Err(MssqlError::MalformedRow(format!("SMALLDATETIME must be 4 bytes, got {}", bytes.len())));
    }
    let days = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
    let minutes = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
    let (y, m, d) = civil_from_days(i64::from(days) - DAYS_1900_01_01_TO_1970_01_01);
    Ok(format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:00", minutes / 60, minutes % 60))
}

/// Pure-function tests for the DECIMAL/date/GUID wire-format math above —
/// no live server needed, unlike almost everything else in this crate's
/// test suite, since these are plain byte-in/text-out conversions.
#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_well_known_reference_points() {
        assert_eq!(civil_from_days(0), (1970, 1, 1), "Unix epoch");
        assert_eq!(civil_from_days(-1), (1969, 12, 31), "day before epoch");
        assert_eq!(civil_from_days(10_957), (2000, 1, 1), "Y2K, 30 years after epoch incl. 7 leap years");
        assert_eq!(civil_from_days(-719_162), (1, 1, 1), "0001-01-01, SQL Server's DATE epoch");
    }

    #[test]
    fn fixed_point_formatting_places_the_decimal_point_and_sign_correctly() {
        assert_eq!(format_fixed_point(123, 2, true), "1.23");
        assert_eq!(format_fixed_point(4, 2, true), "0.04");
        assert_eq!(format_fixed_point(0, 2, true), "0.00");
        assert_eq!(format_fixed_point(123, 0, true), "123");
        assert_eq!(format_fixed_point(123, 2, false), "-1.23");
        assert_eq!(format_fixed_point(0, 2, false), "0.00", "negative zero must not print a minus sign");
    }

    #[test]
    fn decimal_decodes_sign_and_mantissa_from_the_wire_format() {
        // sign byte (1 = positive) + 4-byte LE mantissa (123), scale 2.
        assert_eq!(format_decimal(&[1, 123, 0, 0, 0], 2).unwrap(), "1.23");
        assert_eq!(format_decimal(&[0, 123, 0, 0, 0], 2).unwrap(), "-1.23");
        assert!(format_decimal(&[], 2).is_err(), "empty input must error, not panic");
    }

    #[test]
    fn guid_formats_the_mixed_endian_wire_layout_as_standard_text() {
        let bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        assert_eq!(format_guid(&bytes).unwrap(), "04030201-0605-0807-090A-0B0C0D0E0F10");
        assert!(format_guid(&bytes[..15]).is_err(), "wrong length must error, not panic");
    }

    #[test]
    fn date_decodes_days_since_0001_01_01() {
        assert_eq!(format_date(&[0, 0, 0]).unwrap(), "0001-01-01");
        // 719162 = DAYS_0001_01_01_TO_1970_01_01, so this must land on the Unix epoch date.
        let bytes = 719_162u32.to_le_bytes();
        assert_eq!(format_date(&bytes[..3]).unwrap(), "1970-01-01");
    }

    #[test]
    fn time_scales_the_stored_ticks_by_the_column_scale() {
        // scale 0: value is whole seconds. 3661s = 01:01:01.
        let bytes = 3661u32.to_le_bytes();
        assert_eq!(format_time(&bytes[..3], 0).unwrap(), "01:01:01");
        // scale 7: value is already 100ns ticks. 1 second + 5,000,000 (0.5s) = 00:00:01.5000000.
        let bytes = 15_000_000u64.to_le_bytes();
        assert_eq!(format_time(&bytes[..5], 7).unwrap(), "00:00:01.5000000");
    }

    #[test]
    fn money_and_smallmoney_decode_the_scaled_integer() {
        // MONEY: hi=0, lo=12345 -> 1.2345, stored as two LE u32 halves.
        let mut bytes = [0u8; 8];
        bytes[4..8].copy_from_slice(&12_345u32.to_le_bytes());
        assert_eq!(format_money(&bytes).unwrap(), "1.2345");

        assert_eq!(format_money4(&(-500i32).to_le_bytes()).unwrap(), "-0.0500");
    }
}

/// Decodes one column's value from `cursor`, advancing it past exactly that
/// column's bytes — the per-type dispatch `tds-protocol`'s `RawRow`/`NbcRow`
/// don't provide (see [`QueryResult`]'s doc comment for why). Mirrors
/// `RawRow::decode_column_value`'s (private) dispatch table byte-for-byte,
/// since that's what actually produced the bytes in `RawRow`/`NbcRow`'s
/// `data` — not the original wire format for every type (`Text`/`NText`/
/// `Image` in particular get re-encoded as PLP; see [`read_plp_bytes`]).
///
/// Covers `NULL`/`BIT`/`INT*`/`FLOAT*`/`NVARCHAR`/`NCHAR`/`NTEXT` as typed
/// [`ColumnValue`]s. Everything else this crate doesn't have a typed
/// representation for yet (`DECIMAL`/`NUMERIC`, `DATE`/`TIME`/`DATETIME*`,
/// `MONEY*`, `GUID`, legacy single-byte `CHAR`/`VARCHAR`/`TEXT`,
/// `VARBINARY`, `XML`, `UDT`) is still correctly *framed* (the right number
/// of bytes consumed, so later columns in the same row stay aligned) and
/// returned as `ColumnValue::Bytes` rather than dropped or misparsed.
/// `TypeId::Tvp` can't appear in row data at all — `tds-protocol` itself
/// rejects it before a `Row`/`NbcRow` token carrying one could ever reach
/// this function (`RawRow::decode` errors first).
fn decode_one_column_value(cursor: &mut &[u8], col: &ColumnData) -> Result<ColumnValue, MssqlError> {
    let eof = || MssqlError::MalformedRow("unexpected end of row data".to_string());
    let bad_width = |what: &str, len: usize| MssqlError::MalformedRow(format!("unexpected {what} width {len}"));

    Ok(match col.type_id {
        TypeId::Null => ColumnValue::Null,
        TypeId::Bit => {
            if cursor.remaining() < 1 {
                return Err(eof());
            }
            ColumnValue::Bit(cursor.get_u8() != 0)
        }
        TypeId::Int1 => {
            if cursor.remaining() < 1 {
                return Err(eof());
            }
            ColumnValue::Int(cursor.get_u8() as i64)
        }
        TypeId::Int2 => {
            if cursor.remaining() < 2 {
                return Err(eof());
            }
            ColumnValue::Int(cursor.get_u16_le() as i64)
        }
        TypeId::Int4 => {
            if cursor.remaining() < 4 {
                return Err(eof());
            }
            ColumnValue::Int(cursor.get_u32_le() as i64)
        }
        TypeId::Int8 => {
            if cursor.remaining() < 8 {
                return Err(eof());
            }
            ColumnValue::Int(cursor.get_u64_le() as i64)
        }
        TypeId::Float4 => {
            if cursor.remaining() < 4 {
                return Err(eof());
            }
            ColumnValue::Float(f32::from_bits(cursor.get_u32_le()) as f64)
        }
        TypeId::Float8 => {
            if cursor.remaining() < 8 {
                return Err(eof());
            }
            ColumnValue::Float(f64::from_bits(cursor.get_u64_le()))
        }
        // Fixed-width, non-nullable forms.
        TypeId::Money => {
            if cursor.remaining() < 8 {
                return Err(eof());
            }
            ColumnValue::Decimal(format_money(&cursor.copy_to_bytes(8))?)
        }
        TypeId::Money4 => {
            if cursor.remaining() < 4 {
                return Err(eof());
            }
            ColumnValue::Decimal(format_money4(&cursor.copy_to_bytes(4))?)
        }
        TypeId::DateTime => {
            if cursor.remaining() < 8 {
                return Err(eof());
            }
            ColumnValue::DateTime(format_old_datetime(&cursor.copy_to_bytes(8))?)
        }
        TypeId::DateTime4 => {
            if cursor.remaining() < 4 {
                return Err(eof());
            }
            ColumnValue::DateTime(format_small_datetime(&cursor.copy_to_bytes(4))?)
        }

        TypeId::IntN => match read_bytelen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Int(match bytes.len() {
                1 => bytes[0] as i64,
                2 => i16::from_le_bytes(bytes[..2].try_into().unwrap()) as i64,
                4 => i32::from_le_bytes(bytes[..4].try_into().unwrap()) as i64,
                8 => i64::from_le_bytes(bytes[..8].try_into().unwrap()),
                n => return Err(bad_width("IntN", n)),
            }),
        },
        TypeId::BitN => match read_bytelen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) if bytes.len() == 1 => ColumnValue::Bit(bytes[0] != 0),
            Some(bytes) => return Err(bad_width("BitN", bytes.len())),
        },
        TypeId::FloatN => match read_bytelen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Float(match bytes.len() {
                4 => f32::from_le_bytes(bytes[..4].try_into().unwrap()) as f64,
                8 => f64::from_le_bytes(bytes[..8].try_into().unwrap()),
                n => return Err(bad_width("FloatN", n)),
            }),
        },

        // Still not decoded into a typed ColumnValue — needs the column's
        // collation to pick a codepage (CHAR/VARCHAR) or is genuine binary
        // data with no further structure (BINARY/VARBINARY) — framed
        // correctly and kept as raw bytes either way.
        TypeId::Char | TypeId::VarChar | TypeId::Binary | TypeId::VarBinary => {
            match read_bytelen_prefixed(cursor)? {
                None => ColumnValue::Null,
                Some(bytes) => ColumnValue::Bytes(bytes),
            }
        }

        TypeId::MoneyN => match read_bytelen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Decimal(match bytes.len() {
                4 => format_money4(&bytes)?,
                8 => format_money(&bytes)?,
                n => return Err(bad_width("MoneyN", n)),
            }),
        },
        TypeId::DateTimeN => match read_bytelen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::DateTime(match bytes.len() {
                4 => format_small_datetime(&bytes)?,
                8 => format_old_datetime(&bytes)?,
                n => return Err(bad_width("DateTimeN", n)),
            }),
        },
        TypeId::Guid => match read_bytelen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Guid(format_guid(&bytes)?),
        },
        TypeId::Decimal | TypeId::Numeric | TypeId::DecimalN | TypeId::NumericN => {
            let scale = column_scale(col)?;
            match read_bytelen_prefixed(cursor)? {
                None => ColumnValue::Null,
                Some(bytes) => ColumnValue::Decimal(format_decimal(&bytes, scale)?),
            }
        }
        TypeId::Date => match read_bytelen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::DateTime(format_date(&bytes)?),
        },
        TypeId::Time => {
            let scale = column_scale(col)?;
            match read_bytelen_prefixed(cursor)? {
                None => ColumnValue::Null,
                Some(bytes) => ColumnValue::DateTime(format_time(&bytes, scale)?),
            }
        }
        TypeId::DateTime2 => {
            let scale = column_scale(col)?;
            match read_bytelen_prefixed(cursor)? {
                None => ColumnValue::Null,
                Some(bytes) => ColumnValue::DateTime(format_datetime2(&bytes, scale)?),
            }
        }
        TypeId::DateTimeOffset => {
            let scale = column_scale(col)?;
            match read_bytelen_prefixed(cursor)? {
                None => ColumnValue::Null,
                Some(bytes) => ColumnValue::DateTime(format_datetimeoffset(&bytes, scale)?),
            }
        }

        TypeId::NVarChar => {
            let raw = if col.type_info.max_length == Some(0xFFFF) {
                read_plp_bytes(cursor)?
            } else {
                read_ushortlen_prefixed(cursor)?
            };
            match raw {
                None => ColumnValue::Null,
                Some(bytes) => ColumnValue::Text(utf16le_to_string(&bytes)),
            }
        }
        TypeId::NChar => match read_ushortlen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Text(utf16le_to_string(&bytes)),
        },
        TypeId::NText => match read_plp_bytes(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Text(utf16le_to_string(&bytes)),
        },

        TypeId::BigVarChar | TypeId::BigVarBinary => {
            let raw = if col.type_info.max_length == Some(0xFFFF) {
                read_plp_bytes(cursor)?
            } else {
                read_ushortlen_prefixed(cursor)?
            };
            match raw {
                None => ColumnValue::Null,
                Some(bytes) => ColumnValue::Bytes(bytes),
            }
        }
        TypeId::BigChar | TypeId::BigBinary => match read_ushortlen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Bytes(bytes),
        },
        TypeId::Text | TypeId::Image => match read_plp_bytes(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Bytes(bytes),
        },
        TypeId::Xml | TypeId::Udt => match read_plp_bytes(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Bytes(bytes),
        },
        TypeId::Variant => match read_intlen_prefixed(cursor)? {
            None => ColumnValue::Null,
            Some(bytes) => ColumnValue::Bytes(bytes),
        },

        TypeId::Tvp => {
            return Err(MssqlError::MalformedRow(
                "TVP cannot appear in row data".to_string(),
            ));
        }
        other => {
            return Err(MssqlError::MalformedRow(format!(
                "unsupported column type {other:?}"
            )));
        }
    })
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
    let (packet_type, _status, body) = read_tds_message(stream).await?;
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

    let (packet_type, _status, body) = read_tds_message(backend).await?;
    if packet_type != PacketType::TabularResult {
        return Err(MssqlError::UnexpectedPacketType(
            packet_type,
            "expected a TabularResult SqlBatch response from the backend".to_string(),
        ));
    }

    write_tds_message(frontend, PacketType::TabularResult, &body).await
}

/// Relays one client request to `backend` **verbatim** — whatever
/// `packet_type`/`body` actually are — and its response verbatim back to
/// `frontend`, whatever packet type the backend used for *that*.
///
/// Unlike [`relay_sql_batch`] (which decodes SQL text and re-encodes a fresh
/// `SqlBatch` packet), this never looks at the content at all: a proxy
/// doesn't need to understand `SqlBatch` vs. `Rpc` (stored procedure calls —
/// see [`client_rpc_call`]) vs. anything else TDS defines to forward it,
/// only to know where a message starts and ends, which the TDS packet
/// header already gives for free regardless of type. This is what makes
/// [`run_proxy_session`] handle stored procedure calls and everything else
/// without per-packet-type code.
///
/// `status` is the client's raw request status byte, forwarded to the
/// backend as-is (see [`write_tds_message_with_status`]) rather than
/// collapsed to a plain end-of-message — a pooled client connection sets
/// `RESET_CONNECTION` here, and the real backend needs to see it to actually
/// reset session state as the client expects.
///
/// **Cancel support.** A real client can send an `Attention` packet at any
/// time while a request is outstanding (SSMS's "Cancel Executing Query",
/// or a command-timeout firing) — MS-TDS doesn't restrict it to *after* the
/// response finishes. While waiting for `backend`'s response, this also
/// watches `frontend` concurrently (`tokio::select!`): an `Attention`
/// arriving is relayed to `backend` immediately (real SQL Server then ends
/// the in-flight response with a `DONE` token carrying the `DONE_ATTN`
/// status bit, rather than completing normally — the caller sees this the
/// same as any other response, no special handling needed on this end)
/// instead of sitting unread until the backend eventually finishes on its
/// own — which is what a plain sequential write-then-read here would do,
/// making cancel a silent no-op. MARS aside (not supported — see the
/// crate-level docs), a client isn't expected to send anything *other* than
/// `Attention` while a request is outstanding; anything else is an error.
pub async fn relay_one_message(
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    frontend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    packet_type: PacketType,
    status: u8,
    body: &[u8],
) -> Result<(), MssqlError> {
    write_tds_message_with_status(backend, packet_type, status, body).await?;

    loop {
        tokio::select! {
            biased;

            response = read_tds_message(backend) => {
                let (response_type, _response_status, response_body) = response?;
                return write_tds_message(frontend, response_type, &response_body).await;
            }

            next = read_tds_message(frontend) => {
                let (next_type, next_status, next_body) = next?;
                if next_type != PacketType::Attention {
                    return Err(MssqlError::UnexpectedPacketType(
                        next_type,
                        "expected an Attention (cancel) packet or nothing while a request is outstanding (MARS not supported)".to_string(),
                    ));
                }
                tracing::debug!("relaying client Attention (cancel) while a request is outstanding");
                write_tds_message_with_status(backend, PacketType::Attention, next_status, &next_body).await?;
                // Keep looping: still waiting for backend's response, which
                // should now end in a DONE_ATTN-flagged DONE token instead
                // of completing normally.
            }
        }
    }
}

/// A server-side stream that may or may not have been upgraded to TLS during
/// PreLogin — [`server_negotiate_prelogin_and_maybe_tls`]'s return type.
/// Exists because a caller offering *optional* encryption needs one concrete
/// type to hand [`run_authenticated_relay_session`] regardless of which way
/// PreLogin went; without it the caller would need two entirely separate
/// copies of "LOGIN7 through the relay loop", one generic over `S` and one
/// over `TlsStream<TlsPreloginWrapper<S>>`. Implements
/// `AsyncRead + AsyncWrite` by delegating to whichever variant is present.
pub enum MaybeTlsStream<S> {
    Plain(S),
    /// Boxed because `TlsStream` is large relative to a bare socket and this
    /// enum otherwise pays that size on the `Plain` arm too.
    Tls(Box<tokio_rustls::server::TlsStream<TlsPreloginWrapper<S>>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTlsStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Reads a client's PreLogin request and offers encryption back only if
/// `tls_acceptor` is `Some` *and* the client asked for it (anything other
/// than `EncryptionLevel::NotSupported`) — otherwise responds
/// `NotSupported` and the session stays in the clear, same as
/// [`run_proxy_session`]'s fixed-`requested_encryption` behavior. When both
/// hold, upgrades via [`server_upgrade_to_tls`] right after the PreLogin
/// response, exactly as TDS 7.x requires (see that function's doc comment
/// for the TLS-1.2-only requirement this crate's TLS support has).
///
/// Returns a [`MaybeTlsStream`] wrapping whichever happened — pass it to
/// [`run_authenticated_relay_session`] to continue the session (LOGIN7
/// onward) over the (possibly now encrypted) connection.
pub async fn server_negotiate_prelogin_and_maybe_tls<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    tls_acceptor: Option<&tokio_rustls::TlsAcceptor>,
) -> Result<MaybeTlsStream<S>, MssqlError> {
    let client_prelogin = server_read_prelogin(&mut stream).await?;
    let use_tls = tls_acceptor.is_some() && client_prelogin.encryption != EncryptionLevel::NotSupported;
    let response_encryption = if use_tls {
        EncryptionLevel::On
    } else {
        EncryptionLevel::NotSupported
    };
    tracing::debug!(
        client_requested_encryption = ?client_prelogin.encryption,
        client_mars = client_prelogin.mars,
        client_instance = ?client_prelogin.instance,
        our_offer = ?response_encryption,
        "received client PreLogin"
    );
    server_send_prelogin_response(
        &mut stream,
        &PreLogin::new().with_encryption(response_encryption),
    )
    .await?;

    if use_tls {
        let acceptor = tls_acceptor.expect("use_tls is only true when tls_acceptor is Some");
        let tls_stream = server_upgrade_to_tls(stream, acceptor).await?;
        Ok(MaybeTlsStream::Tls(Box::new(tls_stream)))
    } else {
        Ok(MaybeTlsStream::Plain(stream))
    }
}

/// Runs a full proxy session on `frontend`: the PreLogin + LOGIN7 handshake
/// (`check_credentials` decides success — see [`server_authenticate_with`]),
/// then loops relaying every subsequent request to `backend` (already
/// connected and authenticated by the caller) via [`relay_one_message`],
/// verbatim, regardless of packet type — `SqlBatch`, `Rpc` (stored procedure
/// calls), or anything else TDS defines, all pass through unexamined.
///
/// Always responds to PreLogin with `requested_encryption` verbatim and
/// never upgrades to TLS — fine for a caller that only ever wants cleartext
/// (every test in this crate), but a caller that wants to offer real
/// encryption to clients that ask for it needs a stream that can *become*
/// TLS-wrapped partway through, which this function's `&mut (impl ...)`
/// frontend parameter can't do (its concrete type is fixed by the caller
/// before the call). Use [`server_negotiate_prelogin_and_maybe_tls`] +
/// [`run_authenticated_relay_session`] directly instead for that — this
/// function is now a thin wrapper over exactly those two calls, kept for
/// every existing cleartext-only caller/test.
pub async fn run_proxy_session(
    frontend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    requested_encryption: EncryptionLevel,
    check_credentials: impl FnOnce(&str, &str) -> bool,
    backend_login_response: &[u8],
) -> Result<(), MssqlError> {
    let client_prelogin = server_read_prelogin(frontend).await?;
    tracing::debug!(
        client_requested_encryption = ?client_prelogin.encryption,
        client_mars = client_prelogin.mars,
        client_instance = ?client_prelogin.instance,
        our_offer = ?requested_encryption,
        "received client PreLogin"
    );
    server_send_prelogin_response(
        frontend,
        &PreLogin::new().with_encryption(requested_encryption),
    )
    .await?;

    run_authenticated_relay_session(frontend, backend, check_credentials, backend_login_response)
        .await
}

/// The LOGIN7-through-relay-loop half of [`run_proxy_session`], split out so
/// a caller that needs to negotiate TLS *between* PreLogin and LOGIN7 (see
/// [`server_negotiate_prelogin_and_maybe_tls`]) can do that on the frontend
/// stream first, then hand the (possibly now TLS-wrapped) stream here —
/// `run_proxy_session` itself can't do this since its `&mut (impl ...)`
/// frontend parameter's concrete type is fixed before the call, and
/// upgrading to TLS partway through changes that type ([`MaybeTlsStream`]
/// exists to give both branches one concrete type to hand this function).
///
/// `check_credentials` decides success (see [`server_authenticate_with`]),
/// then the function loops relaying every subsequent request to `backend`
/// (already connected and authenticated by the caller) via
/// [`relay_one_message`], verbatim, regardless of packet type — `SqlBatch`,
/// `Rpc` (stored procedure calls), or anything else TDS defines, all pass
/// through unexamined.
///
/// A clean disconnect (the frontend closing the connection between
/// requests) ends the loop with `Ok(())`, not an error; anything else
/// reading the next request is propagated as a real error. This doesn't yet
/// distinguish "closed between requests" from "closed mid-packet" — both
/// surface as the same `UnexpectedEof`, treated the same way (session
/// over) — good enough for this milestone, worth splitting only if a real
/// deployment needs to tell the two apart.
pub async fn run_authenticated_relay_session(
    frontend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    check_credentials: impl FnOnce(&str, &str) -> bool,
    backend_login_response: &[u8],
) -> Result<(), MssqlError> {
    // Inlines server_authenticate_with's body instead of calling it, so the
    // decoded LOGIN7 fields are available to log before the response is
    // built — worth the small duplication for the diagnostics.
    let login = server_read_login7(frontend).await?;
    tracing::debug!(
        username = %login.username,
        hostname = %login.hostname,
        app_name = %login.app_name,
        database = %login.database,
        integrated_security = login.option_flags2.integrated_security,
        "received client LOGIN7"
    );
    let authenticated = check_credentials(&login.username, &login.password);
    tracing::debug!(username = %login.username, authenticated, "credential check result");
    if authenticated {
        // Relay the *real* backend's LOGIN7-success response verbatim,
        // rather than a hand-built LOGINACK-only response — real SQL Server
        // also sends EnvChange(Database)/EnvChange(SqlCollation)/
        // EnvChange(PacketSize)/Info alongside LOGINACK, and a real client's
        // driver (e.g. SSMS's Microsoft.Data.SqlClient) rejects a response
        // missing those as an invalid protocol negotiation. See
        // client_login7_sql_auth's doc comment.
        write_tds_message(frontend, PacketType::TabularResult, backend_login_response).await?;
    } else {
        let response = build_login_failure_response("Login failed for user");
        write_tds_message(frontend, PacketType::TabularResult, &response).await?;
        return Err(MssqlError::LoginRejected(
            "credential check failed".to_string(),
        ));
    }

    run_relay_loop(frontend, backend).await
}

/// The post-login relay loop shared by [`run_authenticated_relay_session`]
/// and any caller (like `warpgate-protocol-mssql`'s real integration into
/// `warpgate`) that authenticates through a different path than a plain
/// `check_credentials` closure — e.g. Warpgate's own `DbAuthTransport`/
/// `run_db_authorization`, which needs LOGIN7 read (for the username-encoded
/// target selector) *before* the success/failure response can be built, not
/// bundled into one call the way [`run_authenticated_relay_session`] does
/// it. Split out so that integration doesn't have to duplicate this loop.
///
/// A clean disconnect (the frontend closing the connection between
/// requests) ends the loop with `Ok(())`, not an error; anything else
/// reading the next request is propagated as a real error.
pub async fn run_relay_loop(
    frontend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<(), MssqlError> {
    loop {
        let (packet_type, status, body) = match read_tds_message(frontend).await {
            Ok(message) => message,
            Err(MssqlError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::debug!("frontend disconnected cleanly, ending session");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(error = %e, "error reading next client request");
                return Err(e);
            }
        };
        tracing::debug!(
            ?packet_type,
            status = format_args!("{status:#04x}"),
            body_len = body.len(),
            "relaying client request"
        );
        relay_one_message(backend, frontend, packet_type, status, &body).await?;
    }
}

/// `warpgate-core`'s `ProtocolServer` implementation for MSSQL — this is
/// what a real `warpgate` deployment actually runs, mirroring
/// `warpgate-protocol-mysql`'s `MySQLProtocolServer::bind()` closely. Per
/// connection: negotiate PreLogin (offering TLS only if a client asks,
/// [`server_negotiate_prelogin_and_maybe_tls`]), then hand off to
/// [`session::MssqlSession`] for LOGIN7 through the auth-gated relay loop.
///
/// TLS is pinned to 1.2 here for the same reason documented on
/// [`server_upgrade_to_tls`]: a real, reproduced bug in `mssql-tls`'s
/// `TlsPreloginWrapper` under TLS 1.3 in the server role. The crypto
/// provider is passed explicitly (`ServerConfig::builder_with_provider`)
/// rather than relying on a process-global `install_default()` — this
/// crate's own TLS tests already do the same, and a shared `warpgate`
/// process running MySQL/Postgres alongside this must not fight over global
/// rustls state.
pub struct MssqlProtocolServer {
    services: Services,
}

impl MssqlProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self { services: services.clone() }
    }
}

impl ProtocolServer for MssqlProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("MSSQL requires a TLS certificate and key")?;

        let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ResolveServerCert(Arc::new(
            certificate_and_key.into(),
        ))));
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        let listener = address.tcp_accept_stream().await?;
        let services = self.services;

        Ok(async move {
            accept_loop(
                "MSSQL connection",
                listener,
                proxy_protocol,
                move |stream, remote_address| {
                    let tls_acceptor = tls_acceptor.clone();
                    let services = services.clone();
                    async move {
                        let (session_handle, mut abort_rx) = MssqlSessionHandle::new();

                        let server_handle = State::register_session(
                            &services.state,
                            crate::session::PROTOCOL_NAME,
                            SessionStateInit {
                                remote_address: Some(remote_address),
                                handle: Box::new(session_handle),
                            },
                        )
                        .await
                        .context("registering session")?;

                        let wrapped_stream = {
                            let guard = server_handle.lock().await;
                            guard.wrap_stream(stream).await?
                        };

                        let frontend = server_negotiate_prelogin_and_maybe_tls(
                            wrapped_stream,
                            Some(&tls_acceptor),
                        )
                        .await?;

                        let session =
                            MssqlSession::new(server_handle, services, frontend, remote_address)
                                .await;
                        let span = session.make_logging_span();
                        tokio::select! {
                            result = session.run().instrument(span) => match result {
                                Ok(()) => info!("Session ended"),
                                Err(e) => error!(error=%e, "Session failed"),
                            },
                            _ = abort_rx.recv() => {
                                warn!("Session aborted by admin");
                            },
                        }

                        Ok(())
                    }
                },
            )
            .await;
            Ok(())
        }
        .boxed())
    }

    fn name(&self) -> &'static str {
        "MSSQL"
    }
}

impl std::fmt::Debug for MssqlProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MssqlProtocolServer").finish()
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

    /// Proves `decode_one_column_value` against real values from a live
    /// server, not just correct framing: every type this crate decodes into
    /// a typed `ColumnValue` (`INT`, `BIT`, `FLOAT`, `NVARCHAR`, `DECIMAL`,
    /// `DATE`, `GUID`, `MONEY`, and NULLs of both a fixed-width and a
    /// variable-width type), plus one legacy type it still deliberately
    /// leaves as `ColumnValue::Bytes` (`VARCHAR` — needs collation to
    /// decode correctly, which this crate doesn't track), checked last so a
    /// framing bug anywhere earlier in the row would desync it too.
    #[tokio::test]
    async fn decodes_typed_column_values_from_a_real_select() {
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

        let result = client_sql_batch(
            &mut stream,
            "SELECT 42 AS i, CAST(1 AS BIT) AS b, CAST(3.5 AS FLOAT) AS f, \
             N'hello' AS s, CAST(NULL AS INT) AS n, CAST(1.23 AS DECIMAL(5,2)) AS d, \
             CAST(NULL AS NVARCHAR(10)) AS sn, CAST(NULL AS DECIMAL(5,2)) AS dn, \
             CAST('2024-03-15' AS DATE) AS dt, NEWID() AS g, \
             CAST(19.99 AS MONEY) AS mn, CAST('abc' AS VARCHAR(10)) AS legacy",
        )
        .await
        .expect("typed SELECT should succeed");

        assert_eq!(
            result.column_names,
            vec!["i", "b", "f", "s", "n", "d", "sn", "dn", "dt", "g", "mn", "legacy"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(result.rows.len(), 1);
        let row = &result.rows[0];
        assert_eq!(row[0], ColumnValue::Int(42));
        assert_eq!(row[1], ColumnValue::Bit(true));
        assert_eq!(row[2], ColumnValue::Float(3.5));
        assert_eq!(row[3], ColumnValue::Text("hello".to_string()));
        assert_eq!(row[4], ColumnValue::Null, "NULL INT (bytelen-prefixed) must decode as Null");
        assert_eq!(row[5], ColumnValue::Decimal("1.23".to_string()));
        assert_eq!(row[6], ColumnValue::Null, "NULL NVARCHAR (ushortlen-prefixed) must decode as Null");
        assert_eq!(row[7], ColumnValue::Null, "NULL DECIMAL must decode as Null, not an empty mantissa");
        assert_eq!(row[8], ColumnValue::DateTime("2024-03-15".to_string()));
        match &row[9] {
            ColumnValue::Guid(g) => {
                assert_eq!(g.len(), 36, "GUID text must be 36 chars: {g}");
                assert_eq!(
                    g.chars().filter(|&c| c == '-').count(),
                    4,
                    "GUID text must have 4 dashes: {g}"
                );
            }
            other => panic!("expected ColumnValue::Guid, got {other:?}"),
        }
        assert_eq!(row[10], ColumnValue::Decimal("19.9900".to_string()));
        // Legacy VARCHAR still isn't decoded into text — needs the column's
        // collation, which this crate doesn't track — just proving it's
        // still correctly framed as the last column in the row.
        assert!(matches!(&row[11], ColumnValue::Bytes(b) if !b.is_empty()));
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
        let backend_login_response = client_login7_sql_auth(&mut backend, "sa", &password)
            .await
            .expect("LOGIN7 with the real backend should succeed");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut frontend, _) = listener.accept().await.expect("accept");
            run_proxy_session(
                &mut frontend,
                &mut backend,
                EncryptionLevel::NotSupported,
                |u, p| u == "proxyuser" && p == "proxypass",
                &backend_login_response,
            )
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

    /// Regression test for a real bug found live against SSMS: a large
    /// request (Object Explorer's server-object enumeration query, 8+KB)
    /// spans multiple physical TDS packets when read from the client, but
    /// `relay_one_message` used to write the fully-reassembled body back out
    /// as a single oversized packet when forwarding to the backend —
    /// violating the packet size negotiated in LOGIN7/advertised via
    /// `EnvChange(PacketSize)`. A real SQL Server just stopped responding
    /// (no error either side, session hung forever) rather than erroring.
    /// Reproduced here with a `SELECT` whose literal text alone exceeds
    /// `MAX_TDS_PACKET_SIZE`, forcing the same multi-packet request
    /// `write_tds_message_with_status` must now re-chunk correctly.
    #[tokio::test]
    async fn proxy_session_relays_a_request_spanning_multiple_tds_packets() {
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
        let backend_login_response = client_login7_sql_auth(&mut backend, "sa", &password)
            .await
            .expect("LOGIN7 with the real backend should succeed");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut frontend, _) = listener.accept().await.expect("accept");
            run_proxy_session(
                &mut frontend,
                &mut backend,
                EncryptionLevel::NotSupported,
                |u, p| u == "proxyuser" && p == "proxypass",
                &backend_login_response,
            )
            .await
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our proxy");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake with our proxy");
        client_login7_sql_auth(&mut client_stream, "proxyuser", "proxypass")
            .await
            .expect("LOGIN7 with our proxy should succeed");

        // A literal string long enough that the encoded SqlBatch body alone
        // clears MAX_TDS_PACKET_SIZE (4096), forcing client_sql_batch to
        // send this as more than one physical TDS packet.
        let padding = "x".repeat(6000);
        let sql = format!("SELECT LEN('{padding}') AS n");
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(10), client_sql_batch(&mut client_stream, &sql))
                .await
                .expect("query relayed through our proxy should not hang")
                .expect("query relayed through our proxy should succeed");
        assert_eq!(result.column_names, vec!["n".to_string()]);
        assert_eq!(result.done_row_count, Some(1));

        drop(client_stream);
        server_task
            .await
            .expect("server task panicked")
            .expect("a clean client disconnect must end the session with Ok(()), not an error");
    }

    /// Proves the actual path the redeployed `proxy_server` example now
    /// takes for a client that asks for encryption:
    /// `server_negotiate_prelogin_and_maybe_tls` upgrades the frontend leg
    /// to TLS while the backend leg (already logged in before this function
    /// is even called, same as every other proxy test here) stays
    /// cleartext — proxy encryption is a property of the client-facing
    /// connection, not a requirement that the backend also be encrypted.
    /// Also proves the *other* branch of the same function in the same
    /// test: a second, plain client connecting to the same acceptor without
    /// requesting encryption must stay in the clear, not be forced onto
    /// TLS.
    #[tokio::test]
    async fn proxy_session_negotiates_tls_with_client_when_requested() {
        if !live_test_enabled() {
            eprintln!("skipping: set WARPGATE_MSSQL_TEST=1 to run against a live SQL Server");
            return;
        }
        let password = std::env::var("WARPGATE_MSSQL_TEST_SA_PASSWORD")
            .expect("WARPGATE_MSSQL_TEST_SA_PASSWORD must be set for the login test");

        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate a throwaway self-signed certificate");
        let cert_der = cert.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("build a rustls ServerConfig from the throwaway cert");
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        async fn serve_one(
            listener: &tokio::net::TcpListener,
            tls_acceptor: &tokio_rustls::TlsAcceptor,
            password: &str,
        ) -> Result<(), MssqlError> {
            let (raw_frontend, _) = listener.accept().await.expect("accept");
            let mut frontend =
                server_negotiate_prelogin_and_maybe_tls(raw_frontend, Some(tls_acceptor)).await?;

            let mut backend = connect().await;
            client_prelogin_handshake(&mut backend, EncryptionLevel::NotSupported)
                .await
                .expect("PreLogin handshake with the real backend");
            let backend_login_response = client_login7_sql_auth(&mut backend, "sa", password)
                .await
                .expect("LOGIN7 with the real backend should succeed");

            run_authenticated_relay_session(
                &mut frontend,
                &mut backend,
                |u, p| u == "proxyuser" && p == "proxypass",
                &backend_login_response,
            )
            .await
        }

        // Encrypted client.
        let password_clone = password.clone();
        let tls_acceptor_clone = tls_acceptor.clone();
        let server_task = tokio::spawn(async move {
            serve_one(&listener, &tls_acceptor_clone, &password_clone).await
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our proxy");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::Required)
            .await
            .expect("PreLogin handshake requesting encryption");
        let mut client_tls_stream = client_upgrade_to_tls(client_stream, "localhost", true)
            .await
            .expect("client-side TLS handshake against the proxy's throwaway cert");
        client_login7_sql_auth(&mut client_tls_stream, "proxyuser", "proxypass")
            .await
            .expect("LOGIN7 over TLS against our proxy should succeed");
        let result = client_sql_batch(&mut client_tls_stream, "SELECT 1 AS n")
            .await
            .expect("query over TLS relayed through our proxy should succeed");
        assert_eq!(result.column_names, vec!["n".to_string()]);
        assert_eq!(result.done_row_count, Some(1));
        drop(client_tls_stream);
        server_task
            .await
            .expect("server task panicked")
            .expect("a clean client disconnect must end the session with Ok(()), not an error");

        // Plain client against the same acceptor (a fresh listener on a new
        // ephemeral port, to avoid any TIME_WAIT flakiness rebinding the
        // first port) — must stay cleartext, not be forced onto TLS just
        // because the acceptor is configured.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a second ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");
        let server_task =
            tokio::spawn(async move { serve_one(&listener, &tls_acceptor, &password).await });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our proxy");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("plain PreLogin handshake");
        client_login7_sql_auth(&mut client_stream, "proxyuser", "proxypass")
            .await
            .expect("LOGIN7 in the clear against our proxy should succeed");
        let result = client_sql_batch(&mut client_stream, "SELECT 2 AS m")
            .await
            .expect("plain query relayed through our proxy should succeed");
        assert_eq!(result.column_names, vec!["m".to_string()]);
        assert_eq!(result.done_row_count, Some(1));
        drop(client_stream);
        server_task
            .await
            .expect("server task panicked")
            .expect("a clean client disconnect must end the session with Ok(()), not an error");
    }

    /// Answers a real question directly: does the proxy handle stored
    /// procedure calls, not just ad-hoc `SqlBatch` text? Real drivers call
    /// `sp_executesql` (and named stored procedures) via a dedicated `Rpc`
    /// packet type, not a `SqlBatch` containing literal `EXEC ...` text.
    /// Since `run_proxy_session` relays *any* packet type verbatim
    /// (`relay_one_message`, not `relay_sql_batch`'s SqlBatch-specific
    /// decode/re-encode), this needs no RPC-specific code in the session
    /// loop at all — proven here with a genuine `RpcRequest::execute_sql`
    /// packet against the real backend, parsed with the same
    /// `client_rpc_call` a real caller would use.
    #[tokio::test]
    async fn proxy_session_relays_an_rpc_stored_procedure_call() {
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
        let backend_login_response = client_login7_sql_auth(&mut backend, "sa", &password)
            .await
            .expect("LOGIN7 with the real backend should succeed");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut frontend, _) = listener.accept().await.expect("accept");
            run_proxy_session(
                &mut frontend,
                &mut backend,
                EncryptionLevel::NotSupported,
                |u, p| u == "proxyuser" && p == "proxypass",
                &backend_login_response,
            )
            .await
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our proxy");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake with our proxy");
        client_login7_sql_auth(&mut client_stream, "proxyuser", "proxypass")
            .await
            .expect("LOGIN7 with our proxy should succeed");

        let request = tds_protocol::RpcRequest::execute_sql("SELECT 1 AS n", vec![]);
        let result = client_rpc_call(&mut client_stream, &request)
            .await
            .expect("sp_executesql relayed through our proxy should succeed");
        assert_eq!(result.column_names, vec!["n".to_string()]);
        assert_eq!(result.done_row_count, Some(1));

        drop(client_stream);
        server_task
            .await
            .expect("server task panicked")
            .expect("a clean client disconnect must end the session with Ok(())");
    }

    /// Proves cancel actually interrupts a running query, not just that an
    /// `Attention` packet doesn't crash the proxy: a `WAITFOR DELAY` that
    /// would otherwise take 5 seconds is cancelled ~300ms in, and the whole
    /// exchange must finish well under that delay — proof the `Attention`
    /// was actually relayed to the backend while the query was still
    /// running (see `relay_one_message`'s doc comment for why that
    /// previously couldn't happen at all: nothing read the frontend again
    /// until the in-flight request's response had already arrived in
    /// full). Also checks the completion isn't the normal `count`-only
    /// `DONE` a full 5s `WAITFOR` would produce — found empirically that a
    /// cancelled `WAITFOR` sets `DONE`'s `error` bit, not `DONE_ATTN` as
    /// MS-TDS's general attention-handling docs would suggest.
    #[tokio::test]
    async fn cancels_a_long_running_query_via_attention() {
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
        let backend_login_response = client_login7_sql_auth(&mut backend, "sa", &password)
            .await
            .expect("LOGIN7 with the real backend should succeed");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");

        let server_task = tokio::spawn(async move {
            let (mut frontend, _) = listener.accept().await.expect("accept");
            run_proxy_session(
                &mut frontend,
                &mut backend,
                EncryptionLevel::NotSupported,
                |u, p| u == "proxyuser" && p == "proxypass",
                &backend_login_response,
            )
            .await
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect to our proxy");
        client_prelogin_handshake(&mut client_stream, EncryptionLevel::NotSupported)
            .await
            .expect("PreLogin handshake with our proxy");
        client_login7_sql_auth(&mut client_stream, "proxyuser", "proxypass")
            .await
            .expect("LOGIN7 with our proxy should succeed");

        let payload = SqlBatch::new("WAITFOR DELAY '00:00:05'").encode();
        write_tds_message(&mut client_stream, PacketType::SqlBatch, &payload)
            .await
            .expect("send the long-running query");

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        write_tds_message(&mut client_stream, PacketType::Attention, &[])
            .await
            .expect("send Attention (cancel)");

        let started = std::time::Instant::now();
        let (packet_type, _status, body) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            read_tds_message(&mut client_stream),
        )
        .await
        .expect("response should arrive well before the 5s WAITFOR would have finished on its own")
        .expect("read the (cancelled) query's response");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "cancel should interrupt the query almost immediately, not wait out most of the delay"
        );
        assert_eq!(packet_type, PacketType::TabularResult);

        // Empirically, a WAITFOR cancelled via Attention completes with a
        // single DONE token whose `error` bit is set (`attn` stays false) —
        // not the `DONE_ATTN` status MS-TDS's general attention docs would
        // suggest. Trusting the real server's behavior over the spec
        // reading: what actually proves cancellation happened is that this
        // is NOT the normal `count`-only completion a full 5s WAITFOR would
        // produce, combined with the timing assertion above.
        let mut parser = TokenParser::new(body);
        let mut saw_abnormal_done = false;
        while let Some(token) = parser.next_token().expect("parse the cancelled response's tokens") {
            if let Token::Done(done) = token {
                if done.status.error || done.status.attn {
                    saw_abnormal_done = true;
                }
            }
        }
        assert!(
            saw_abnormal_done,
            "response must carry a DONE token flagged as an abnormal completion (error or attn), not a normal one"
        );

        drop(client_stream);
        server_task
            .await
            .expect("server task panicked")
            .expect("a clean client disconnect must end the session with Ok(())");
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

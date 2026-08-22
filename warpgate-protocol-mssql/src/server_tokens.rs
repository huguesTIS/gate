//! Hand-written encoders for the tokens a server sends in a LOGIN7 response.
//!
//! `tds-protocol` has no `LoginAck::encode()` or `ServerError`/`Token::Error`
//! encoder — the same client-only asymmetry as LOGIN7's missing `decode()`
//! (see `login7_decode`'s module docs), mirrored: a client driver only ever
//! needs to *read* these, never write them. `Done::encode()` does exist and
//! is reused as-is (`tds-protocol` implements both directions for
//! `Done`/`DoneProc`/`DoneInProc`, unlike `LoginAck`/`Error`).
//!
//! Wire format verified against `LoginAck::decode`/`ServerError::decode` in
//! `tds-protocol`'s own source (the exact inverse), and against MS-TDS
//! §2.2.7.13 (LOGINACK) / §2.2.7.9 (ERROR).

use bytes::{BufMut, Bytes, BytesMut};
use tds_protocol::codec::{write_b_varchar, write_us_varchar};
use tds_protocol::{Done, DoneStatus, LoginAck, ServerError, TokenType};

/// Encodes a LOGINACK token: type byte + length-prefixed body (interface +
/// TDS version + program name + program version).
pub fn encode_login_ack(ack: &LoginAck) -> Bytes {
    let mut body = BytesMut::new();
    body.put_u8(ack.interface);
    body.put_u32_le(ack.tds_version);
    write_b_varchar(&mut body, &ack.prog_name);
    body.put_u32_le(ack.prog_version);

    let mut out = BytesMut::with_capacity(3 + body.len());
    out.put_u8(TokenType::LoginAck as u8);
    out.put_u16_le(body.len() as u16);
    out.extend_from_slice(&body);
    out.freeze()
}

/// Encodes an ERROR token: type byte + length-prefixed body (number, state,
/// class, message, server name, procedure name, line).
pub fn encode_error(err: &ServerError) -> Bytes {
    let mut body = BytesMut::new();
    body.put_i32_le(err.number);
    body.put_u8(err.state);
    body.put_u8(err.class);
    write_us_varchar(&mut body, &err.message);
    write_b_varchar(&mut body, &err.server);
    write_b_varchar(&mut body, &err.procedure);
    body.put_i32_le(err.line);

    let mut out = BytesMut::with_capacity(3 + body.len());
    out.put_u8(TokenType::Error as u8);
    out.put_u16_le(body.len() as u16);
    out.extend_from_slice(&body);
    out.freeze()
}

/// Builds a successful LOGIN7 response: LOGINACK followed by a DONE token
/// (no ENVCHANGE — the bare minimum a client needs to recognize success;
/// `client_login7_sql_auth` only looks for the LOGINACK token and stops).
pub fn build_login_success_response(tds_version_raw: u32) -> Bytes {
    let ack = LoginAck {
        interface: 1, // SQL_TSQL, per MS-TDS — matches what real SQL Server sends
        tds_version: tds_version_raw,
        prog_name: "warpgate".to_string(),
        prog_version: 0,
    };
    let mut out = BytesMut::new();
    out.extend_from_slice(&encode_login_ack(&ack));

    let done = Done {
        status: DoneStatus::default(),
        cur_cmd: 0,
        row_count: 0,
    };
    done.encode(&mut out);
    out.freeze()
}

/// Builds a failed LOGIN7 response: ERROR followed by a DONE token with the
/// error bit set. `number`/`class` follow real SQL Server's own convention
/// for "Login failed for user" (18456, severity 14) so a real client's error
/// classification (fatal vs. retryable) behaves the same as against a real
/// server, not just something this crate's own client happens to accept.
pub fn build_login_failure_response(message: &str) -> Bytes {
    let err = ServerError {
        number: 18456,
        state: 1,
        class: 14,
        message: message.to_string(),
        server: String::new(),
        procedure: String::new(),
        line: 1,
    };
    let mut out = BytesMut::new();
    out.extend_from_slice(&encode_error(&err));

    // `DoneStatus` is `#[non_exhaustive]` — no struct-literal construction
    // from outside `tds-protocol`, even with `..Default::default()`; only
    // `Default::default()` itself, then field mutation, works here.
    let mut status = DoneStatus::default();
    status.error = true;
    status.srverror = true;
    let done = Done { status, cur_cmd: 0, row_count: 0 };
    done.encode(&mut out);
    out.freeze()
}

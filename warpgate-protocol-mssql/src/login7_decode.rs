//! Hand-written LOGIN7 decoder.
//!
//! `tds-protocol` has no `Login7::decode()` — its parent project
//! (`mssql-client`) is a client driver that only ever needs to *write* a
//! LOGIN7, never read one. See `ARCHITECTURE_TECHNIQUE.md` §12 for the full
//! writeup of that gap. This module implements the missing decode direction
//! directly against MS-TDS §2.2.6.4, as the exact inverse of
//! `tds_protocol::Login7::encode()` (verified field-by-field against that
//! function's source): same 94-byte fixed header, same absolute-offset
//! variable-length field table, same password obfuscation.
//!
//! Field offsets in the wire format are absolute from the start of the whole
//! LOGIN7 payload (matching `encode()`, which starts its `offset` counter at
//! `LOGIN7_HEADER_SIZE`) — so every field is read directly from `data` at its
//! own offset, not sequentially. This is deliberate, not just convenient: a
//! real client is free to lay out its variable-length fields in any order
//! (or with gaps) as long as the offset table is correct, so a decoder that
//! assumed `encode()`'s particular field order would be fragile against any
//! client other than this crate's own.

use bytes::{Buf, Bytes};
use tds_protocol::codec::read_utf16_string;
use tds_protocol::login7::LOGIN7_HEADER_SIZE;
use tds_protocol::{
    FeatureExtension, FeatureId, Login7, OptionFlags1, OptionFlags2, OptionFlags3, TdsVersion,
    TypeFlags,
};

use crate::MssqlError;

fn slice_field<'a>(
    data: &'a [u8],
    offset: u32,
    byte_len: usize,
    field: &str,
) -> Result<&'a [u8], MssqlError> {
    let start = offset as usize;
    let end = start.checked_add(byte_len).ok_or_else(|| {
        MssqlError::MalformedLogin7(format!("{field}: offset {offset} + length {byte_len} overflows"))
    })?;
    data.get(start..end).ok_or_else(|| {
        MssqlError::MalformedLogin7(format!(
            "{field}: byte range {start}..{end} is out of bounds (payload is {} bytes)",
            data.len()
        ))
    })
}

fn read_str_field(data: &[u8], offset: u16, char_len: u16, field: &str) -> Result<String, MssqlError> {
    let bytes = slice_field(data, u32::from(offset), char_len as usize * 2, field)?;
    read_utf16_string(&mut &bytes[..], char_len as usize)
        .ok_or_else(|| MssqlError::MalformedLogin7(format!("{field}: truncated UTF-16 data")))
}

/// Inverse of `Login7::write_obfuscated_password`: per byte, XOR 0xA5 then
/// rotate left 4 bits (undoing the encoder's rotate-right-then-XOR), then
/// reassemble as UTF-16LE (low byte first, matching how the encoder split
/// each code unit).
fn read_obfuscated_password_field(
    data: &[u8],
    offset: u16,
    char_len: u16,
    field: &str,
) -> Result<String, MssqlError> {
    let bytes = slice_field(data, u32::from(offset), char_len as usize * 2, field)?;
    let mut units = Vec::with_capacity(char_len as usize);
    for pair in bytes.chunks_exact(2) {
        let low = (pair[0] ^ 0xA5).rotate_left(4);
        let high = (pair[1] ^ 0xA5).rotate_left(4);
        units.push(u16::from(low) | (u16::from(high) << 8));
    }
    Ok(String::from_utf16_lossy(&units))
}

const fn option_flags1_from_byte(b: u8) -> OptionFlags1 {
    OptionFlags1 {
        byte_order_be: b & 0x01 != 0,
        char_ebcdic: b & 0x02 != 0,
        // fFloat is bits 2-3 (0 = IEEE 754). Extracted properly here even
        // though to_byte() never actually encodes this field (always
        // writes 00 regardless of self.float_ieee) — a real client that
        // sets non-IEEE bits should still decode correctly.
        float_ieee: (b >> 2) & 0x03 == 0,
        dump_load_off: b & 0x10 != 0,
        use_db_notify: b & 0x20 != 0,
        database_fatal: b & 0x40 != 0,
        set_lang_warn: b & 0x80 != 0,
    }
}

const fn option_flags2_from_byte(b: u8) -> OptionFlags2 {
    OptionFlags2 {
        language_fatal: b & 0x01 != 0,
        odbc: b & 0x02 != 0,
        tran_boundary: b & 0x04 != 0,
        cache_connect: b & 0x08 != 0,
        user_type: (b >> 4) & 0x07,
        integrated_security: b & 0x80 != 0,
    }
}

const fn type_flags_from_byte(b: u8) -> TypeFlags {
    TypeFlags {
        sql_type: b & 0x0F,
        oledb: b & 0x10 != 0,
        read_only_intent: b & 0x20 != 0,
    }
}

const fn option_flags3_from_byte(b: u8) -> OptionFlags3 {
    OptionFlags3 {
        change_password: b & 0x01 != 0,
        user_instance: b & 0x02 != 0,
        send_yukon_binary_xml: b & 0x04 != 0,
        unknown_collation_handling: b & 0x08 != 0,
        extension: b & 0x10 != 0,
    }
}

fn feature_id_from_u8(b: u8) -> Result<FeatureId, MssqlError> {
    match b {
        0x01 => Ok(FeatureId::SessionRecovery),
        0x02 => Ok(FeatureId::FedAuth),
        0x04 => Ok(FeatureId::ColumnEncryption),
        0x05 => Ok(FeatureId::GlobalTransactions),
        0x08 => Ok(FeatureId::AzureSqlSupport),
        0x09 => Ok(FeatureId::DataClassification),
        0x0A => Ok(FeatureId::Utf8Support),
        0x0B => Ok(FeatureId::AzureSqlDnsCaching),
        other => Err(MssqlError::MalformedLogin7(format!(
            "unknown feature extension id 0x{other:02x}"
        ))),
    }
}

/// Decodes the `FeatureExt` TLV block: `(feature_id: u8, len: u32 LE, data: [u8; len])*`,
/// terminated by `0xFF`.
fn decode_feature_extensions(data: &[u8], start: u32) -> Result<Vec<FeatureExtension>, MssqlError> {
    let mut features = Vec::new();
    let mut offset = start;
    loop {
        let id_byte = *slice_field(data, offset, 1, "feature extension id")?
            .first()
            .expect("slice_field(len=1) always returns exactly one byte");
        offset += 1;
        if id_byte == FeatureId::Terminator as u8 {
            break;
        }
        let feature_id = feature_id_from_u8(id_byte)?;
        let len_bytes = slice_field(data, offset, 4, "feature extension length")?;
        let len = u32::from_le_bytes(len_bytes.try_into().expect("slice_field(len=4)"));
        offset += 4;
        let fdata = slice_field(data, offset, len as usize, "feature extension data")?;
        offset += len;
        features.push(FeatureExtension { feature_id, data: Bytes::copy_from_slice(fdata) });
    }
    Ok(features)
}

/// Decodes a LOGIN7 packet body (the payload of a `PacketType::Tds7Login`
/// packet, header already stripped) into `tds_protocol`'s own `Login7`
/// struct — reusing that type rather than duplicating its field list, even
/// though the crate itself never constructs one this way.
pub fn decode_login7(data: &[u8]) -> Result<Login7, MssqlError> {
    if data.len() < LOGIN7_HEADER_SIZE {
        return Err(MssqlError::MalformedLogin7(format!(
            "LOGIN7 payload is {} bytes, need at least the {LOGIN7_HEADER_SIZE}-byte fixed header",
            data.len()
        )));
    }

    let mut r = data;
    let _length = r.get_u32_le();
    let tds_version = TdsVersion::new(r.get_u32_le());
    let packet_size = r.get_u32_le();
    let client_prog_version = r.get_u32_le();
    let client_pid = r.get_u32_le();
    let connection_id = r.get_u32_le();
    let option_flags1 = option_flags1_from_byte(r.get_u8());
    let option_flags2 = option_flags2_from_byte(r.get_u8());
    let type_flags = type_flags_from_byte(r.get_u8());
    let option_flags3 = option_flags3_from_byte(r.get_u8());
    let client_timezone = r.get_i32_le();
    let client_lcid = r.get_u32_le();

    let hostname_offset = r.get_u16_le();
    let hostname_len = r.get_u16_le();
    let username_offset = r.get_u16_le();
    let username_len = r.get_u16_le();
    let password_offset = r.get_u16_le();
    let password_len = r.get_u16_le();
    let app_name_offset = r.get_u16_le();
    let app_name_len = r.get_u16_le();
    let server_name_offset = r.get_u16_le();
    let server_name_len = r.get_u16_le();
    let extension_offset = r.get_u16_le();
    let extension_len = r.get_u16_le();
    let library_name_offset = r.get_u16_le();
    let library_name_len = r.get_u16_le();
    let language_offset = r.get_u16_le();
    let language_len = r.get_u16_le();
    let database_offset = r.get_u16_le();
    let database_len = r.get_u16_le();

    let mut client_id = [0u8; 6];
    r.copy_to_slice(&mut client_id);

    let sspi_offset = r.get_u16_le();
    let cb_sspi = r.get_u16_le();
    let attach_db_offset = r.get_u16_le();
    let attach_db_len = r.get_u16_le();
    let new_password_offset = r.get_u16_le();
    let new_password_len = r.get_u16_le();
    let cb_sspi_long = r.get_u32_le();

    let hostname = read_str_field(data, hostname_offset, hostname_len, "hostname")?;
    let username = read_str_field(data, username_offset, username_len, "username")?;
    let password = read_obfuscated_password_field(data, password_offset, password_len, "password")?;
    let app_name = read_str_field(data, app_name_offset, app_name_len, "app_name")?;
    let server_name = read_str_field(data, server_name_offset, server_name_len, "server_name")?;
    let library_name = read_str_field(data, library_name_offset, library_name_len, "library_name")?;
    let language = read_str_field(data, language_offset, language_len, "language")?;
    let database = read_str_field(data, database_offset, database_len, "database")?;

    // When fExtension is set, this slot holds a 4-byte pointer to the
    // FeatureExt block instead of the `unused` string — see encode()'s
    // comment on the same asymmetry (and the bug it once caused there).
    let (unused, features) = if option_flags3.extension {
        let pointer_bytes = slice_field(data, u32::from(extension_offset), 4, "feature_ext_pointer")?;
        let feature_data_offset = u32::from_le_bytes(
            pointer_bytes.try_into().expect("slice_field(len=4) returns 4 bytes"),
        );
        (String::new(), decode_feature_extensions(data, feature_data_offset)?)
    } else {
        (read_str_field(data, extension_offset, extension_len, "unused")?, Vec::new())
    };

    let sspi_len = if cb_sspi == 0xFFFF { cb_sspi_long as usize } else { cb_sspi as usize };
    let sspi_data = slice_field(data, u32::from(sspi_offset), sspi_len, "sspi_data")?.to_vec();

    let attach_db_file = read_str_field(data, attach_db_offset, attach_db_len, "attach_db_file")?;
    let new_password = if new_password_len == 0 {
        String::new()
    } else {
        read_obfuscated_password_field(data, new_password_offset, new_password_len, "new_password")?
    };

    Ok(Login7 {
        tds_version,
        packet_size,
        client_prog_version,
        client_pid,
        connection_id,
        option_flags1,
        option_flags2,
        type_flags,
        option_flags3,
        client_timezone,
        client_lcid,
        hostname,
        username,
        password,
        app_name,
        server_name,
        unused,
        library_name,
        language,
        database,
        client_id,
        sspi_data,
        attach_db_file,
        new_password,
        features,
    })
}

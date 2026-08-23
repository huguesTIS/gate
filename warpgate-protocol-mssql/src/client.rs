//! Dials a real MSSQL target, honoring `TargetMssqlOptions` — the piece that
//! turns this crate's already-proven client-side functions
//! (`client_prelogin_handshake`/`client_upgrade_to_tls`/`client_login7_sql_auth`)
//! into something driven by Warpgate's own target configuration, mirroring
//! `warpgate-protocol-mysql/src/client.rs`'s shape.

use bytes::Bytes;
use tokio::net::TcpStream;
use tracing::info;
use warpgate_common::{DatabaseTargetAuth, TargetMssqlOptions, WarpgateError};
use warpgate_tls::TlsMode;

use crate::{
    EncryptionLevel, MaybeTlsClientStream, MssqlError, client_login7_sql_auth,
    client_prelogin_handshake, client_upgrade_to_tls,
};

pub struct MssqlClient {
    pub stream: MaybeTlsClientStream<TcpStream>,
    /// The backend's real LOGIN7-success response, relayed verbatim to the
    /// frontend once it's authenticated too — see `client_login7_sql_auth`'s
    /// doc comment for why a hand-built LOGINACK-only response isn't enough.
    pub login_response: Bytes,
}

impl MssqlClient {
    pub async fn connect(target: &TargetMssqlOptions) -> Result<Self, MssqlError> {
        let mut stream = TcpStream::connect((target.host.clone(), target.port)).await?;
        stream.set_nodelay(true)?;

        let requested_encryption = match target.tls.mode {
            TlsMode::Disabled => EncryptionLevel::NotSupported,
            TlsMode::Preferred | TlsMode::Required => EncryptionLevel::On,
        };

        let prelogin_response =
            client_prelogin_handshake(&mut stream, requested_encryption).await?;

        let server_offers_tls = !matches!(prelogin_response.encryption, EncryptionLevel::NotSupported);
        if target.tls.mode == TlsMode::Required && !server_offers_tls {
            return Err(MssqlError::EncryptionNotSupported);
        }
        let use_tls = target.tls.mode != TlsMode::Disabled && server_offers_tls;

        let effective_password = match target.effective_auth() {
            DatabaseTargetAuth::Password(auth) => auth
                .password
                .reveal()
                .await
                .map_err(WarpgateError::from)?
                .expose_secret()
                .clone(),
            DatabaseTargetAuth::IamRole(_) => {
                return Err(MssqlError::TargetAuthNotSupported("IAM role"));
            }
            DatabaseTargetAuth::Requester(_) => {
                // Relaying the connecting user's own credential isn't
                // implemented yet for any database protocol — see
                // ARCHITECTURE_TECHNIQUE.md §10 ("Mode Requester"); MySQL's
                // client has the identical limitation, not something new
                // introduced here.
                return Err(MssqlError::TargetAuthNotSupported("Requester"));
            }
        };

        if use_tls {
            info!("Upgrading target connection to TLS");
            let mut tls_stream =
                client_upgrade_to_tls(stream, &target.host, !target.tls.verify).await?;
            let login_response =
                client_login7_sql_auth(&mut tls_stream, &target.username, &effective_password)
                    .await?;
            Ok(Self {
                stream: MaybeTlsClientStream::Tls(Box::new(tls_stream)),
                login_response,
            })
        } else {
            let login_response =
                client_login7_sql_auth(&mut stream, &target.username, &effective_password).await?;
            Ok(Self {
                stream: MaybeTlsClientStream::Plain(stream),
                login_response,
            })
        }
    }
}

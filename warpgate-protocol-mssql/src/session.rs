//! Real, auth-gated MSSQL sessions — the integration point that turns this
//! crate's already-proven protocol logic (PreLogin/LOGIN7, TLS-in-TDS,
//! generic relay, typed decoding) into a governed PAM target rather than a
//! standalone proxy authenticating against one hardcoded credential (see
//! `examples/proxy_server.rs`, which still does exactly that and is
//! untouched by this module).
//!
//! Mirrors `warpgate-protocol-mysql/src/session.rs`'s shape closely — same
//! `DbAuthTransport` contract, same `user:target` selector convention, same
//! `run_db_authorization` call — with one real difference forced by TDS
//! itself: MySQL's `send_auth_ok` can write a fresh, self-contained OK
//! packet before ever dialing the real target, because its handshake
//! doesn't need anything from that target. MSSQL's success response *does*
//! — a hand-built LOGINACK alone is what `Microsoft.Data.SqlClient`
//! rejected earlier this session (see `client_login7_sql_auth`'s doc
//! comment) — so `send_auth_ok` here only marks the `AuthOkPermit` consumed
//! and defers the actual bytes until after the backend dial succeeds and a
//! real LOGIN7 response is in hand (`run_authorized`).

use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;
use warpgate_common::auth::AuthSelector;
use warpgate_common::{Protocol, Secret, TargetOptions};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::{
    AuthOkPermit, DbAuthTransport, Services, TargetAuthorization, WarpgateServerHandle,
    run_db_authorization,
};

use crate::client::MssqlClient;
use crate::{
    MaybeTlsStream, MssqlError, build_login_failure_response, run_relay_loop, server_read_login7,
    write_tds_message,
};

pub const PROTOCOL_NAME: Protocol = Protocol::Mssql;

pub struct MssqlSession<S: AsyncRead + AsyncWrite + Send + Unpin> {
    frontend: MaybeTlsStream<S>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: Uuid,
    services: Services,
    remote_address: SocketAddr,
    username: Option<String>,
    /// TDS carries the password in LOGIN7, same as MySQL's handshake — no
    /// second prompt is possible, so a repeat request denies the login.
    handshake_password: Option<Secret<String>>,
    /// Set by `send_auth_ok` once `run_db_authorization` accepts the login —
    /// consumes the `AuthOkPermit` (so a second call can't compile), but the
    /// actual response bytes are written later, once they're known. See this
    /// module's doc comment for why.
    pending_success: bool,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> DbAuthTransport for MssqlSession<S> {
    type Error = MssqlError;

    const PROTOCOL: Protocol = PROTOCOL_NAME;
    const SUPPORTS_WEB_APPROVAL: bool = false;

    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, MssqlError> {
        Ok(self.handshake_password.take())
    }

    async fn send_auth_ok(&mut self, _permit: AuthOkPermit) -> Result<(), MssqlError> {
        self.pending_success = true;
        Ok(())
    }

    async fn external_url(&mut self) -> Result<Url, MssqlError> {
        Ok(construct_external_url(None, &*self.services.config.lock().await, None).await?)
    }

    /// LOGIN7 has no packet for showing the user a link mid-handshake, same
    /// limitation MySQL has — a policy requiring web approval can't be
    /// satisfied over MSSQL.
    async fn send_web_approval_prompt(
        &mut self,
        _url: &Url,
        _identification_string: &str,
    ) -> Result<bool, MssqlError> {
        warn!("Web user approval is not supported over MSSQL");
        Ok(false)
    }

    async fn send_denied(&mut self) -> Result<(), MssqlError> {
        let response = build_login_failure_response("Warpgate access denied");
        write_tds_message_pub(&mut self.frontend, &response).await
    }
}

/// `write_tds_message` is crate-private; this session module is also inside
/// the crate, but the helper is `pub(crate)`-scoped implicitly through the
/// `crate::` import above — kept as a thin named wrapper only where the
/// packet type is always the same (`TabularResult`), to avoid repeating it.
async fn write_tds_message_pub(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    payload: &[u8],
) -> Result<(), MssqlError> {
    write_tds_message(stream, crate::PacketType::TabularResult, payload).await
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> MssqlSession<S> {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        frontend: MaybeTlsStream<S>,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.id();
        Self {
            frontend,
            server_handle,
            id,
            services,
            remote_address,
            username: None,
            handshake_password: None,
            pending_success: false,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(ref username) = self.username {
            tracing::info_span!("MSSQL", session=%self.id, session_username=%username, %client_ip)
        } else {
            tracing::info_span!("MSSQL", session=%self.id, %client_ip)
        }
    }

    pub async fn run(mut self) -> Result<(), MssqlError> {
        let login = server_read_login7(&mut self.frontend).await?;
        info!(
            username = %login.username,
            hostname = %login.hostname,
            app_name = %login.app_name,
            "received client LOGIN7"
        );
        self.username = Some(login.username.clone());
        self.handshake_password = Some(Secret::new(login.password.clone()));

        let selector: AuthSelector = login.username.deref().into();
        let remote_ip = self.remote_address.ip();
        let session_id = self.id;
        let services = self.services.clone();

        let Some(authorization) =
            run_db_authorization(&mut self, &services, session_id, selector, remote_ip).await?
        else {
            return Ok(());
        };

        if !self.pending_success {
            // run_db_authorization only returns Some(..) after calling
            // send_auth_ok — this would mean that contract broke upstream.
            return Err(MssqlError::LoginRejected(
                "authorization succeeded without consuming the AuthOkPermit".to_string(),
            ));
        }

        self.run_authorized(authorization).await
    }

    async fn run_authorized(mut self, authorization: TargetAuthorization) -> Result<(), MssqlError> {
        let (user_info, target) = authorization.into_parts();

        let TargetOptions::Mssql(ref mssql_options) = target.options else {
            warn!("Selected target is not an MSSQL target");
            let response = build_login_failure_response("Warpgate access denied");
            write_tds_message_pub(&mut self.frontend, &response).await?;
            return Ok(());
        };
        let mssql_options = mssql_options.clone();

        {
            let handle = self.server_handle.lock().await;
            handle.set_user_info(user_info).await?;
            handle.set_target(&target).await?;
        }

        let client = match MssqlClient::connect(&mssql_options).await {
            Ok(client) => client,
            Err(error) => {
                warn!(%error, "Target connection failed");
                let response = build_login_failure_response("Warpgate: target connection failed");
                write_tds_message_pub(&mut self.frontend, &response).await?;
                return Err(error);
            }
        };

        write_tds_message_pub(&mut self.frontend, &client.login_response).await?;

        let mut backend = client.stream;
        run_relay_loop(&mut self.frontend, &mut backend).await
    }
}

//! Minimal runnable MSSQL proxy — for actually trying a real client (SSMS,
//! `sqlcmd`, etc.) against this crate's exploratory groundwork, not a
//! production binary. This crate isn't wired into `warpgate` yet (see the
//! crate-level docs) — no `ConfigProvider` auth, no target routing by
//! config, just one fixed backend and one fixed accepted credential pair,
//! both from environment variables.
//!
//! ```text
//! MSSQL_PROXY_LISTEN_ADDR      default 0.0.0.0:14333
//! MSSQL_PROXY_BACKEND_ADDR     required, e.g. 127.0.0.1:14330
//! MSSQL_PROXY_BACKEND_USER     required, SQL-auth username on the real backend
//! MSSQL_PROXY_BACKEND_PASSWORD required
//! MSSQL_PROXY_FRONTEND_USER    required, credential a connecting client must use
//! MSSQL_PROXY_FRONTEND_PASSWORD required
//! ```
//!
//! **Frontend leg supports TLS; backend leg is cleartext only.** On the
//! client-facing side, a throwaway self-signed certificate is generated at
//! startup (`rcgen`, TLS 1.2 only — see [`server_negotiate_prelogin_and_maybe_tls`]'s
//! doc comment for the TLS 1.3 bug in `mssql-tls` this works around) and
//! used to encrypt the session if the connecting client asks for it at
//! PreLogin; a client that doesn't ask stays in the clear, same as before.
//! The proxy-to-real-backend leg still always negotiates
//! `EncryptionLevel::NotSupported` — the throwaway cert has no relationship
//! to the real backend's identity, so there'd be nothing meaningful to
//! validate. A client that requires the *backend itself* to be validated as
//! a real server (as opposed to just "this connection to the proxy is
//! encrypted") shouldn't trust a self-signed cert here — set
//! `TrustServerCertificate=true` (or SSMS's equivalent) to accept it anyway
//! for this exploratory testing.
//!
//! Only `SqlBatch`/`Rpc`/anything else TDS defines relay transparently once
//! a session is authenticated (`relay_one_message` doesn't care about
//! packet type) — but the *initial* PreLogin/LOGIN7 handshake is real,
//! hand-decoded TDS, so expect rough edges with any client this hasn't
//! been tried against yet.
//!
//! Run with (from `warpgate-protocol-mssql/`):
//! ```text
//! RUST_LOG=warpgate_protocol_mssql=debug \
//! MSSQL_PROXY_BACKEND_ADDR=127.0.0.1:14330 \
//! MSSQL_PROXY_BACKEND_USER=sa MSSQL_PROXY_BACKEND_PASSWORD=... \
//! MSSQL_PROXY_FRONTEND_USER=proxyuser MSSQL_PROXY_FRONTEND_PASSWORD=proxypass \
//! cargo run --example proxy_server
//! ```
//!
//! `RUST_LOG=warpgate_protocol_mssql=debug` is the useful one when trying a
//! real client for the first time — `run_proxy_session` logs the client's
//! PreLogin (in particular the encryption level it asked for — the most
//! likely first mismatch with a real driver) and LOGIN7 fields
//! (username/hostname/app_name/database) as soon as they're decoded, and
//! every packet type it relays afterward, before anything has a chance to
//! fail silently.

use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use warpgate_protocol_mssql::{
    EncryptionLevel, MssqlError, client_login7_sql_auth, client_prelogin_handshake,
    run_authenticated_relay_session, server_negotiate_prelogin_and_maybe_tls,
};

/// Builds a `TlsAcceptor` from a fresh throwaway self-signed certificate,
/// pinned to TLS 1.2 — see this file's module doc comment and
/// `server_negotiate_prelogin_and_maybe_tls`'s for why TLS 1.2 specifically.
///
/// **Session resumption disabled on purpose.** Found live: a real client
/// (SSMS) opens many parallel connections and its TLS stack resumes the
/// session on the 2nd+ one once the 1st full handshake completes against
/// this acceptor's cache. An abbreviated (resumed) handshake has a
/// different message-flight order than a full one, and `mssql-tls`'s
/// `TlsPreloginWrapper` — built and tested only against full handshakes —
/// doesn't handle that: the client can legitimately start sending
/// post-handshake application data (its encrypted LOGIN7) before the
/// wrapper's `pending_handshake` flag has been flipped, which the wrapper
/// then rejects with `Expected PreLogin packet (0x12), got 0x17` (0x17 is
/// TLS's own `ApplicationData` record type — a real symptom, not a
/// coincidence). One-off tests never hit this because a single connection
/// against a freshly-built config has nothing to resume from; a real client
/// making several connections against one long-lived proxy process does.
/// Forcing every handshake to be a full one sidesteps the race entirely —
/// not fixing `mssql-tls` itself (upstream bug, not reported yet).
fn build_tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate a throwaway self-signed certificate");
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut server_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("build a rustls ServerConfig from the throwaway cert");
    server_config.session_storage = std::sync::Arc::new(rustls::server::NoServerSessionStorage {});
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config))
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

async fn dial_backend(
    addr: &str,
    username: &str,
    password: &str,
) -> Result<(TcpStream, Bytes), MssqlError> {
    let mut backend = TcpStream::connect(addr).await?;
    client_prelogin_handshake(&mut backend, EncryptionLevel::NotSupported).await?;
    let login_response = client_login7_sql_auth(&mut backend, username, password).await?;
    Ok((backend, login_response))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let listen_addr =
        std::env::var("MSSQL_PROXY_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:14333".to_string());
    let backend_addr = env("MSSQL_PROXY_BACKEND_ADDR");
    let backend_user = env("MSSQL_PROXY_BACKEND_USER");
    let backend_password = env("MSSQL_PROXY_BACKEND_PASSWORD");
    let frontend_user = env("MSSQL_PROXY_FRONTEND_USER");
    let frontend_password = env("MSSQL_PROXY_FRONTEND_PASSWORD");

    let tls_acceptor = build_tls_acceptor();

    let listener = TcpListener::bind(&listen_addr)
        .await
        .unwrap_or_else(|e| panic!("bind {listen_addr}: {e}"));
    println!("MSSQL proxy listening on {listen_addr}, relaying to {backend_addr}");
    println!(
        "Connect a client with SQL Server authentication: user={frontend_user:?} password={frontend_password:?} (encrypted if the client asks, cleartext otherwise — see this example's doc comment)"
    );

    loop {
        let (frontend, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        println!("[{peer}] connected");

        let backend_addr = backend_addr.clone();
        let backend_user = backend_user.clone();
        let backend_password = backend_password.clone();
        let frontend_user = frontend_user.clone();
        let frontend_password = frontend_password.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let mut frontend =
                match server_negotiate_prelogin_and_maybe_tls(frontend, Some(&tls_acceptor)).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        eprintln!("[{peer}] PreLogin/TLS negotiation with client failed: {e}");
                        return;
                    }
                };

            let (mut backend, backend_login_response) =
                match dial_backend(&backend_addr, &backend_user, &backend_password).await {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[{peer}] failed to dial backend {backend_addr}: {e}");
                        return;
                    }
                };

            let result = run_authenticated_relay_session(
                &mut frontend,
                &mut backend,
                |u, p| u == frontend_user && p == frontend_password,
                &backend_login_response,
            )
            .await;

            match result {
                Ok(()) => println!("[{peer}] session ended cleanly"),
                Err(e) => eprintln!("[{peer}] session ended with error: {e}"),
            }
        });
    }
}

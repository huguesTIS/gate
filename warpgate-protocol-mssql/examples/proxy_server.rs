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
//! **Cleartext only.** Both the frontend (client-facing) and backend
//! (proxy-to-real-server) legs negotiate `EncryptionLevel::NotSupported`.
//! Real clients increasingly default to requiring encryption (SSMS
//! included, in recent versions) — if the connection fails immediately at
//! PreLogin, try unchecking "Encrypt connection" / setting `Encrypt=false`
//! (or `Encrypt=Optional`/`TrustServerCertificate=true` depending on the
//! client) in the connection's advanced options. Wiring TLS through here
//! is possible (`client_upgrade_to_tls`/`server_upgrade_to_tls` both exist
//! and are proven — see `ARCHITECTURE_TECHNIQUE.md` §12) but deliberately
//! left out of this example for now: it needs a real or generated
//! certificate and the server side is only proven safe on TLS 1.2 (a real
//! bug in `mssql-tls` under TLS 1.3 — see `server_upgrade_to_tls`'s doc
//! comment), both worth a deliberate choice, not a default baked into an
//! example.
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

use tokio::net::{TcpListener, TcpStream};
use warpgate_protocol_mssql::{
    EncryptionLevel, MssqlError, client_login7_sql_auth, client_prelogin_handshake,
    run_proxy_session,
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

async fn dial_backend(addr: &str, username: &str, password: &str) -> Result<TcpStream, MssqlError> {
    let mut backend = TcpStream::connect(addr).await?;
    client_prelogin_handshake(&mut backend, EncryptionLevel::NotSupported).await?;
    client_login7_sql_auth(&mut backend, username, password).await?;
    Ok(backend)
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

    let listener = TcpListener::bind(&listen_addr)
        .await
        .unwrap_or_else(|e| panic!("bind {listen_addr}: {e}"));
    println!("MSSQL proxy listening on {listen_addr}, relaying to {backend_addr}");
    println!(
        "Connect a client with SQL Server authentication: user={frontend_user:?} password={frontend_password:?} (cleartext, see this example's doc comment)"
    );

    loop {
        let (mut frontend, peer) = match listener.accept().await {
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

        tokio::spawn(async move {
            let mut backend =
                match dial_backend(&backend_addr, &backend_user, &backend_password).await {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[{peer}] failed to dial backend {backend_addr}: {e}");
                        return;
                    }
                };

            let result = run_proxy_session(
                &mut frontend,
                &mut backend,
                EncryptionLevel::NotSupported,
                |u, p| u == frontend_user && p == frontend_password,
            )
            .await;

            match result {
                Ok(()) => println!("[{peer}] session ended cleanly"),
                Err(e) => eprintln!("[{peer}] session ended with error: {e}"),
            }
        });
    }
}

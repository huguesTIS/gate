pub mod ldap_group {
    //! MVP connector: add/remove the target user's DN to/from an LDAP group's
    //! `member` attribute — the cheapest JIT pattern identified in
    //! `WARPGATE_VAUBAN_NETWRIX_ANALYSE.md` §08 ("élévation temporaire par groupe"):
    //! no account creation, just a bounded group membership window.

    use std::collections::HashSet;

    use ldap3::Mod;
    use sea_orm::{DatabaseConnection, EntityTrait};
    use serde::Deserialize;
    use warpgate_common::WarpgateError;
    use warpgate_common::helpers::ldap::resolve_ldap_bind_password;
    use warpgate_db_entities::LdapServer;

    #[derive(Debug, Deserialize)]
    struct Config {
        ldap_server_id: uuid::Uuid,
        group_dn: String,
        /// `{username}` is replaced with the target user's username.
        member_dn_template: String,
    }

    async fn resolve(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(warpgate_ldap::LdapConfig, String, String), WarpgateError> {
        let config: Config = serde_json::from_value(raw_config.clone())?;
        let Some(server) = LdapServer::Entity::find_by_id(config.ldap_server_id)
            .one(db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState(format!(
                "ldap_group action refers to unknown LDAP server {}",
                config.ldap_server_id
            )));
        };
        let mut ldap_config: warpgate_ldap::LdapConfig = (&server).try_into()?;
        resolve_ldap_bind_password(&mut ldap_config).await?;
        let member_dn = config.member_dn_template.replace("{username}", username);
        Ok((ldap_config, config.group_dn, member_dn))
    }

    pub async fn grant(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (ldap_config, group_dn, member_dn) = resolve(db, raw_config, username).await?;
        let mut ldap = warpgate_ldap::connect(&ldap_config).await?;
        let mut members = HashSet::new();
        members.insert(member_dn.as_str());
        ldap.modify(&group_dn, vec![Mod::Add("member", members)])
            .await
            .map_err(|e| WarpgateError::InconsistentState(e.to_string()))?
            .success()
            .map_err(|e| WarpgateError::InconsistentState(e.to_string()))?;
        let _ = ldap.unbind().await;
        Ok(())
    }

    pub async fn remove(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (ldap_config, group_dn, member_dn) = resolve(db, raw_config, username).await?;
        let mut ldap = warpgate_ldap::connect(&ldap_config).await?;
        let mut members = HashSet::new();
        members.insert(member_dn.as_str());
        ldap.modify(&group_dn, vec![Mod::Delete("member", members)])
            .await
            .map_err(|e| WarpgateError::InconsistentState(e.to_string()))?
            .success()
            .map_err(|e| WarpgateError::InconsistentState(e.to_string()))?;
        let _ = ldap.unbind().await;
        Ok(())
    }
}

pub mod ssh_command {
    //! MVP connector: run a single templated shell command over SSH on a fixed
    //! admin credential — the generic "Extensibilité / Run Custom Script" family
    //! from `WARPGATE_VAUBAN_NETWRIX_ANALYSE.md` §08, and the base a later
    //! `windows_local_group`/`ad_domain_group`/`linux_sudoers_rule` connector can
    //! build on (see `ARCHITECTURE_TECHNIQUE.md` §07).
    //!
    //! Deliberately NOT built on `warpgate-protocol-ssh`'s `RemoteClient` — that
    //! crate is the full interactive proxying stack (jump-host chains, PTY,
    //! forwarding, live event streams). This only ever needs "connect, run one
    //! command, read the exit code, disconnect," so a raw `russh::client` session
    //! is ~80 lines here instead of pulling in a crate an order of magnitude
    //! bigger into a lightweight, connector-agnostic engine crate.
    //!
    //! Host key verification reuses the same `known_hosts` table (and the same
    //! admin-facing `POST /ssh/known-hosts` endpoint) the interactive SSH proxy
    //! already exposes — an admin pins the fingerprint there before this
    //! connector's action can ever run. Unlike the interactive proxy path there
    //! is no user here who could be prompted to accept an unknown key on first
    //! use, so an unknown or mismatched key fails closed instead of trusting on
    //! first use. This duplicates `warpgate-protocol-ssh::known_hosts::KnownHosts`'s
    //! ~10-line lookup rather than depending on that crate for it.

    use russh::ChannelMsg;
    use russh::client::{AuthResult, Handler};
    use russh::keys::{PublicKey, PublicKeyBase64};
    use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
    use serde::Deserialize;
    use warpgate_common::WarpgateError;
    use warpgate_db_entities::{KnownHost, SshCredential};

    #[derive(Debug, Deserialize)]
    struct Config {
        ssh_credential_id: uuid::Uuid,
        /// `{username}` is replaced with the target user's username.
        command_template: String,
    }

    struct FailClosedHandler {
        host: String,
        port: i32,
        db: DatabaseConnection,
    }

    impl Handler for FailClosedHandler {
        type Error = russh::Error;

        async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
            let Ok(entries) = KnownHost::Entity::find()
                .filter(KnownHost::Column::Host.eq(&self.host))
                .filter(KnownHost::Column::Port.eq(self.port))
                .filter(KnownHost::Column::KeyType.eq(key.algorithm().as_str()))
                .all(&self.db)
                .await
            else {
                // A DB failure fails closed too — better a wrongly-rejected
                // connection than a silently-unverified one.
                return Ok(false);
            };
            Ok(entries.iter().any(|e| e.key_base64 == key.public_key_base64()))
        }
    }

    async fn resolve(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(SshCredential::Model, String, String), WarpgateError> {
        let config: Config = serde_json::from_value(raw_config.clone())?;
        let Some(credential) = SshCredential::Entity::find_by_id(config.ssh_credential_id)
            .one(db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState(format!(
                "ssh_command action refers to unknown SSH credential {}",
                config.ssh_credential_id
            )));
        };
        let password = warpgate_common::resolve_stored_secret(&credential.password)
            .await?
            .expose_secret()
            .clone();
        let command = config.command_template.replace("{username}", username);
        Ok((credential, password, command))
    }

    async fn run(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, command) = resolve(db, raw_config, username).await?;

        let address = format!("{}:{}", credential.host, credential.port);
        let handler = FailClosedHandler {
            host: credential.host.clone(),
            port: credential.port,
            db: db.clone(),
        };
        let mut session =
            russh::client::connect(Default::default(), address.as_str(), handler)
                .await
                .map_err(|e| WarpgateError::InconsistentState(format!("SSH connect failed: {e}")))?;

        match session
            .authenticate_password(credential.username.clone(), password.as_str())
            .await
            .map_err(|e| WarpgateError::InconsistentState(format!("SSH auth failed: {e}")))?
        {
            AuthResult::Success => {}
            AuthResult::Failure { .. } => {
                return Err(WarpgateError::InconsistentState(
                    "SSH password authentication was rejected".into(),
                ));
            }
        }

        let mut channel = session.channel_open_session().await.map_err(|e| {
            WarpgateError::InconsistentState(format!("SSH channel open failed: {e}"))
        })?;
        channel.exec(true, command.as_bytes()).await.map_err(|e| {
            WarpgateError::InconsistentState(format!("SSH exec failed: {e}"))
        })?;

        let mut exit_status = None;
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::ExitStatus { exit_status: status } = msg {
                exit_status = Some(status);
            }
        }
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;

        match exit_status {
            Some(0) => Ok(()),
            Some(code) => Err(WarpgateError::InconsistentState(format!(
                "Command exited with status {code}"
            ))),
            None => Err(WarpgateError::InconsistentState(
                "SSH command closed without an exit status".into(),
            )),
        }
    }

    pub async fn grant(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        run(db, raw_config, username).await
    }

    pub async fn remove(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        run(db, raw_config, username).await
    }
}

pub mod winrm_powershell {
    //! MVP connector: run a single templated PowerShell script over WinRM on a
    //! fixed admin credential — the Windows/AD counterpart to `ssh_command`,
    //! covering the family of Netwrix-style actions
    //! (`WARPGATE_VAUBAN_NETWRIX_ANALYSE.md` §08) that need `Add-LocalGroupMember`,
    //! `Add-ADGroupMember`, etc. See `ARCHITECTURE_TECHNIQUE.md` §07.
    //!
    //! Crate: `winrm-rs` (MIT/Apache-2.0, async/Tokio, own `reqwest`-based
    //! transport) — its `WinrmClient::run_powershell` already handles the full
    //! shell lifecycle (create/execute/poll/signal/delete) and encodes the
    //! script as `-EncodedCommand` UTF-16LE base64, so this connector is just
    //! resolving the stored credential and mapping the result. NTLM only for
    //! now (the crate's default; Kerberos/CredSSP need extra cargo features
    //! not enabled here — see `ARCHITECTURE_TECHNIQUE.md` §07, add if a real
    //! deployment needs them instead of guessing upfront).

    use sea_orm::{DatabaseConnection, EntityTrait};
    use serde::Deserialize;
    use warpgate_common::WarpgateError;
    use warpgate_db_entities::WinrmCredential;
    use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};

    #[derive(Debug, Deserialize)]
    struct Config {
        winrm_credential_id: uuid::Uuid,
        /// `{username}` is replaced with the target user's username.
        script_template: String,
    }

    async fn resolve(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(WinrmCredential::Model, String, String), WarpgateError> {
        let config: Config = serde_json::from_value(raw_config.clone())?;
        let Some(credential) = WinrmCredential::Entity::find_by_id(config.winrm_credential_id)
            .one(db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState(format!(
                "winrm_powershell action refers to unknown WinRM credential {}",
                config.winrm_credential_id
            )));
        };
        let password = warpgate_common::resolve_stored_secret(&credential.password)
            .await?
            .expose_secret()
            .clone();
        let script = config.script_template.replace("{username}", username);
        Ok((credential, password, script))
    }

    async fn run(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, script) = resolve(db, raw_config, username).await?;

        let config = WinrmConfig {
            port: credential.port as u16,
            use_tls: credential.use_tls,
            auth_method: AuthMethod::Ntlm,
            ..Default::default()
        };
        let creds =
            WinrmCredentials::new(credential.username.clone(), password, credential.domain.clone());
        let client = WinrmClient::new(config, creds).map_err(|e| {
            WarpgateError::InconsistentState(format!("WinRM client setup failed: {e}"))
        })?;

        let output = client
            .run_powershell(&credential.host, &script)
            .await
            .map_err(|e| {
                WarpgateError::InconsistentState(format!("WinRM PowerShell run failed: {e}"))
            })?;

        if output.exit_code == 0 {
            Ok(())
        } else {
            Err(WarpgateError::InconsistentState(format!(
                "PowerShell script exited with status {}: {}",
                output.exit_code,
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    pub async fn grant(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        run(db, raw_config, username).await
    }

    pub async fn remove(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        run(db, raw_config, username).await
    }
}

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
    use russh::keys::{PublicKeyBase64, PublicKeyOrCertificate};
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

        async fn check_server_key(
            &mut self,
            key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            let key = key.public_key();
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

    /// Resolves a stored SSH credential row and its plaintext password —
    /// factored out so Tier 2 connectors (`linux_sudoers_rule`) can reuse the
    /// same credential without going through this connector's free-text
    /// `command_template` config.
    pub(crate) async fn resolve_credential(
        db: &DatabaseConnection,
        ssh_credential_id: uuid::Uuid,
    ) -> Result<(SshCredential::Model, String), WarpgateError> {
        let Some(credential) = SshCredential::Entity::find_by_id(ssh_credential_id)
            .one(db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState(format!(
                "action refers to unknown SSH credential {ssh_credential_id}"
            )));
        };
        let password = warpgate_common::resolve_stored_secret(&credential.password)
            .await?
            .expose_secret()
            .clone();
        Ok((credential, password))
    }

    async fn resolve(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(SshCredential::Model, String, String), WarpgateError> {
        let config: Config = serde_json::from_value(raw_config.clone())?;
        let (credential, password) = resolve_credential(db, config.ssh_credential_id).await?;
        let command = config.command_template.replace("{username}", username);
        Ok((credential, password, command))
    }

    /// Connects, runs `command` to completion, and disconnects. Reused directly
    /// by Tier 2 connectors that build their own validated command instead of
    /// taking one from an admin-supplied template.
    pub(crate) async fn exec(
        db: &DatabaseConnection,
        credential: &SshCredential::Model,
        password: &str,
        command: &str,
    ) -> Result<(), WarpgateError> {
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
            .authenticate_password(credential.username.clone(), password)
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

    async fn run(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, command) = resolve(db, raw_config, username).await?;
        exec(db, &credential, &password, &command).await
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

pub mod linux_sudoers_rule {
    //! Tier 2 connector: grants/revokes passwordless sudo for a fixed set of
    //! commands via a drop-in file under `/etc/sudoers.d/`, over the same SSH
    //! transport `ssh_command` uses. "Hardened" in the sense meant by
    //! `ARCHITECTURE_TECHNIQUE.md` §07: the admin supplies typed parameters (a
    //! rule name, a command list) instead of a free-text shell command, so
    //! there's no way to fat-finger this into running an unrelated command
    //! as root.
    //!
    //! Content is written via a validated sequence rather than editing
    //! `/etc/sudoers` directly: `visudo -c -f` checks syntax on a `.tmp` file
    //! *before* it's moved into place, so a malformed rule never reaches a
    //! spot `sudo` actually reads — a broken `/etc/sudoers.d/*` file can lock
    //! out every admin on the box.
    //!
    //! The rule text is base64-encoded before being sent as part of the
    //! remote command line, sidestepping shell-escaping the command list and
    //! username entirely (base64's alphabet has no shell metacharacters).
    //! Only `rule_name` is used unquoted as a path component, so it's
    //! validated against a strict allowlist instead. Config values (including
    //! `commands`) are admin-authored, same trust boundary as every other
    //! connector's config — an admin who can define this Grant action can
    //! already run anything as this SSH credential's user via `ssh_command`.

    use data_encoding::BASE64;
    use sea_orm::DatabaseConnection;
    use serde::Deserialize;
    use warpgate_common::WarpgateError;
    use warpgate_db_entities::SshCredential;

    use super::ssh_command;

    #[derive(Debug, Deserialize)]
    struct Config {
        ssh_credential_id: uuid::Uuid,
        /// Identifies the drop-in file (`/etc/sudoers.d/{rule_name}`) — must
        /// be `[a-zA-Z0-9_-]+`, checked at run time since it's used unquoted
        /// as a path component.
        rule_name: String,
        /// Commands the granted user may run as root without a password.
        /// `"ALL"` grants full sudo — same meaning as in a real sudoers file.
        commands: Vec<String>,
    }

    fn valid_rule_name(name: &str) -> bool {
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }

    async fn resolve(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
    ) -> Result<(SshCredential::Model, String, String, Vec<String>), WarpgateError> {
        let config: Config = serde_json::from_value(raw_config.clone())?;
        if !valid_rule_name(&config.rule_name) {
            return Err(WarpgateError::InconsistentState(format!(
                "linux_sudoers_rule: invalid rule_name '{}' (must be alphanumeric, '_' or '-' only)",
                config.rule_name
            )));
        }
        if config.commands.is_empty() {
            return Err(WarpgateError::InconsistentState(
                "linux_sudoers_rule: commands must not be empty".into(),
            ));
        }
        let (credential, password) =
            ssh_command::resolve_credential(db, config.ssh_credential_id).await?;
        Ok((credential, password, config.rule_name, config.commands))
    }

    pub async fn grant(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, rule_name, commands) = resolve(db, raw_config).await?;
        let rule = format!("{username} ALL=(ALL) NOPASSWD: {}\n", commands.join(", "));
        let encoded = BASE64.encode(rule.as_bytes());
        let command = format!(
            "printf '%s' '{encoded}' | base64 -d > /etc/sudoers.d/{rule_name}.tmp && \
             visudo -c -f /etc/sudoers.d/{rule_name}.tmp && \
             mv /etc/sudoers.d/{rule_name}.tmp /etc/sudoers.d/{rule_name} && \
             chmod 440 /etc/sudoers.d/{rule_name}"
        );
        ssh_command::exec(db, &credential, &password, &command).await
    }

    pub async fn remove(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        _username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, rule_name, _commands) = resolve(db, raw_config).await?;
        let command = format!("rm -f /etc/sudoers.d/{rule_name}");
        ssh_command::exec(db, &credential, &password, &command).await
    }

    #[cfg(test)]
    mod tests {
        use super::valid_rule_name;

        #[test]
        fn accepts_alphanumeric_dash_underscore() {
            assert!(valid_rule_name("db-admins_01"));
        }

        #[test]
        fn rejects_empty() {
            assert!(!valid_rule_name(""));
        }

        #[test]
        fn rejects_path_traversal() {
            assert!(!valid_rule_name("../../etc/passwd"));
            assert!(!valid_rule_name("foo/bar"));
        }

        #[test]
        fn rejects_whitespace_and_shell_metacharacters() {
            assert!(!valid_rule_name("foo bar"));
            assert!(!valid_rule_name("foo;rm -rf /"));
            assert!(!valid_rule_name("foo$(whoami)"));
        }
    }
}

pub mod windows_local_group {
    //! Tier 2 connector: adds/removes the target user from a local Windows
    //! group via `Add-LocalGroupMember`/`Remove-LocalGroupMember`, over the
    //! same WinRM transport `winrm_powershell` uses. "Hardened" in the sense
    //! meant by `ARCHITECTURE_TECHNIQUE.md` §07: the admin supplies a group
    //! name instead of a free-text script.

    use sea_orm::DatabaseConnection;
    use serde::Deserialize;
    use warpgate_common::WarpgateError;
    use warpgate_db_entities::WinrmCredential;

    use super::winrm_powershell;

    #[derive(Debug, Deserialize)]
    struct Config {
        winrm_credential_id: uuid::Uuid,
        group_name: String,
    }

    /// Safely embeds a literal value in a PowerShell single-quoted string —
    /// doubling an embedded `'` is the only escape single-quoted PowerShell
    /// strings need (no variable expansion, no backtick interpretation).
    fn ps_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    async fn resolve(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
    ) -> Result<(WinrmCredential::Model, String, String), WarpgateError> {
        let config: Config = serde_json::from_value(raw_config.clone())?;
        if config.group_name.is_empty() {
            return Err(WarpgateError::InconsistentState(
                "windows_local_group: group_name must not be empty".into(),
            ));
        }
        let (credential, password) =
            winrm_powershell::resolve_credential(db, config.winrm_credential_id).await?;
        Ok((credential, password, config.group_name))
    }

    pub async fn grant(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, group_name) = resolve(db, raw_config).await?;
        let script = format!(
            "Add-LocalGroupMember -Group {} -Member {} -ErrorAction Stop",
            ps_quote(&group_name),
            ps_quote(username)
        );
        winrm_powershell::run_script(&credential, &password, &script).await
    }

    pub async fn remove(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, group_name) = resolve(db, raw_config).await?;
        let script = format!(
            "Remove-LocalGroupMember -Group {} -Member {} -ErrorAction Stop",
            ps_quote(&group_name),
            ps_quote(username)
        );
        winrm_powershell::run_script(&credential, &password, &script).await
    }

    #[cfg(test)]
    mod tests {
        use super::ps_quote;

        #[test]
        fn quotes_plain_value() {
            assert_eq!(ps_quote("Administrators"), "'Administrators'");
        }

        #[test]
        fn doubles_embedded_single_quotes() {
            assert_eq!(ps_quote("O'Brien"), "'O''Brien'");
        }
    }
}

pub mod ad_domain_group {
    //! Tier 2 connector: adds/removes the target user from an Active
    //! Directory domain group via `Add-ADGroupMember`/`Remove-ADGroupMember`,
    //! over the same WinRM transport `winrm_powershell` uses — same shape as
    //! `windows_local_group`, different cmdlet family. Requires the
    //! `winrm_credentials` row to point at a host with the RSAT
    //! `ActiveDirectory` PowerShell module available (a domain controller, or
    //! a management host with RSAT installed) — `Add-ADGroupMember` doesn't
    //! exist otherwise.
    //!
    //! `warpgate-actions` already has an LDAP-based `ldap_group` connector
    //! that can also manage AD group membership (AD speaks LDAP) — this one
    //! is for deployments that would rather stay in native AD PowerShell
    //! tooling than hand-craft LDAP DN templates. Neither supersedes the
    //! other.

    use sea_orm::DatabaseConnection;
    use serde::Deserialize;
    use warpgate_common::WarpgateError;
    use warpgate_db_entities::WinrmCredential;

    use super::winrm_powershell;

    #[derive(Debug, Deserialize)]
    struct Config {
        winrm_credential_id: uuid::Uuid,
        group_name: String,
    }

    fn ps_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    async fn resolve(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
    ) -> Result<(WinrmCredential::Model, String, String), WarpgateError> {
        let config: Config = serde_json::from_value(raw_config.clone())?;
        if config.group_name.is_empty() {
            return Err(WarpgateError::InconsistentState(
                "ad_domain_group: group_name must not be empty".into(),
            ));
        }
        let (credential, password) =
            winrm_powershell::resolve_credential(db, config.winrm_credential_id).await?;
        Ok((credential, password, config.group_name))
    }

    pub async fn grant(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, group_name) = resolve(db, raw_config).await?;
        let script = format!(
            "Add-ADGroupMember -Identity {} -Members {} -ErrorAction Stop",
            ps_quote(&group_name),
            ps_quote(username)
        );
        winrm_powershell::run_script(&credential, &password, &script).await
    }

    pub async fn remove(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, group_name) = resolve(db, raw_config).await?;
        let script = format!(
            "Remove-ADGroupMember -Identity {} -Members {} -Confirm:$false -ErrorAction Stop",
            ps_quote(&group_name),
            ps_quote(username)
        );
        winrm_powershell::run_script(&credential, &password, &script).await
    }

    #[cfg(test)]
    mod tests {
        use super::ps_quote;

        #[test]
        fn quotes_plain_value() {
            assert_eq!(ps_quote("Domain Admins"), "'Domain Admins'");
        }

        #[test]
        fn doubles_embedded_single_quotes() {
            assert_eq!(ps_quote("O'Brien"), "'O''Brien'");
        }
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

    /// Resolves a stored WinRM credential row and its plaintext password —
    /// factored out so Tier 2 connectors (`windows_local_group`,
    /// `ad_domain_group`) can reuse the same credential without going through
    /// this connector's free-text `script_template` config.
    pub(crate) async fn resolve_credential(
        db: &DatabaseConnection,
        winrm_credential_id: uuid::Uuid,
    ) -> Result<(WinrmCredential::Model, String), WarpgateError> {
        let Some(credential) = WinrmCredential::Entity::find_by_id(winrm_credential_id)
            .one(db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState(format!(
                "action refers to unknown WinRM credential {winrm_credential_id}"
            )));
        };
        let password = warpgate_common::resolve_stored_secret(&credential.password)
            .await?
            .expose_secret()
            .clone();
        Ok((credential, password))
    }

    async fn resolve(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(WinrmCredential::Model, String, String), WarpgateError> {
        let config: Config = serde_json::from_value(raw_config.clone())?;
        let (credential, password) = resolve_credential(db, config.winrm_credential_id).await?;
        let script = config.script_template.replace("{username}", username);
        Ok((credential, password, script))
    }

    /// Connects, runs `script` to completion, and reports a non-zero exit code
    /// as an error. Reused directly by Tier 2 connectors that build their own
    /// validated script instead of taking one from an admin-supplied template.
    pub(crate) async fn run_script(
        credential: &WinrmCredential::Model,
        password: &str,
        script: &str,
    ) -> Result<(), WarpgateError> {
        let config = WinrmConfig {
            port: credential.port as u16,
            use_tls: credential.use_tls,
            auth_method: AuthMethod::Ntlm,
            ..Default::default()
        };
        let creds = WinrmCredentials::new(
            credential.username.clone(),
            password,
            credential.domain.clone(),
        );
        let client = WinrmClient::new(config, creds).map_err(|e| {
            WarpgateError::InconsistentState(format!("WinRM client setup failed: {e}"))
        })?;

        let output = client.run_powershell(&credential.host, script).await.map_err(|e| {
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

    async fn run(
        db: &DatabaseConnection,
        raw_config: &serde_json::Value,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let (credential, password, script) = resolve(db, raw_config, username).await?;
        run_script(&credential, &password, &script).await
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

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
        let ldap_config: warpgate_ldap::LdapConfig = (&server).try_into()?;
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

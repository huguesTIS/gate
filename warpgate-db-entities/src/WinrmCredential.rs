use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

/// A reusable admin WinRM credential the `winrm_powershell` action connector
/// runs PowerShell scripts with — mirrors `SshCredential`'s role for the
/// `ssh_command` connector. See `ARCHITECTURE_TECHNIQUE.md` §07.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "winrm_credentials")]
#[oai(rename = "WinrmCredential")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub name: String,
    pub host: String,
    pub port: i32,
    pub use_tls: bool,
    pub username: String,
    /// Vault reference, envelope-encrypted, or (unmigrated legacy) plaintext —
    /// same `StoredSecret` convention as `LdapServer.bind_password`.
    pub password: String,
    /// NetBIOS domain for NTLM auth. Empty = auto-detect from the server's
    /// challenge (see `winrm_rs::WinrmCredentials`).
    pub domain: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

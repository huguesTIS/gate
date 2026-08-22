use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

/// A reusable admin SSH credential the `ssh_command` action connector runs
/// commands with — mirrors `LdapServer`'s role for the `ldap_group` connector.
/// See `ARCHITECTURE_TECHNIQUE.md` §07.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "ssh_credentials")]
#[oai(rename = "SshCredential")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub name: String,
    pub host: String,
    pub port: i32,
    pub username: String,
    /// Vault reference, envelope-encrypted, or (unmigrated legacy) plaintext —
    /// same `StoredSecret` convention as `LdapServer.bind_password`.
    pub password: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

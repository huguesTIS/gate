use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// How `secret_ref` should be interpreted — see `ARCHITECTURE_TECHNIQUE.md` §10
/// ("`managed_accounts` — pas de secret local"). Neither variant stores a secret
/// (not even encrypted) on this row: the real material lives in OpenBao, this
/// table only maps *which* tiers has *which* account on *which* target.
#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(24))")]
pub enum ManagedAccountCredentialMode {
    /// `secret_ref` is a path into OpenBao's KV engine holding a rotated, static secret.
    #[sea_orm(string_value = "vaulted_secret")]
    VaultedSecret,
    /// `secret_ref` names the OpenBao PKI/SSH role used to mint a short-lived
    /// certificate per session — nothing persists between sessions.
    #[sea_orm(string_value = "ephemeral_certificate")]
    EphemeralCertificate,
}

/// Identity mapping only — *not* a vault. One row = one tiers' account on one
/// target. Lets several tiers each have their own distinct managed account on
/// a target that only has a single `Target.options.auth` field otherwise.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "managed_accounts")]
#[oai(rename = "ManagedAccount")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub target_id: Uuid,
    pub user_group_id: Uuid,
    pub principal_name: String,
    pub credential_mode: ManagedAccountCredentialMode,
    /// OpenBao reference — unusable until OpenBao itself is deployed (see backlog
    /// in `CLAUDE.md`). Never a secret value itself.
    pub secret_ref: Option<String>,
    pub active: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

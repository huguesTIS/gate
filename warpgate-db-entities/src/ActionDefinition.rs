use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ActionKind {
    #[sea_orm(string_value = "grant")]
    Grant,
    #[sea_orm(string_value = "remove")]
    Remove,
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum ConnectorType {
    /// Add/remove the target user's DN to/from an LDAP group's `member` attribute.
    #[sea_orm(string_value = "ldap_group")]
    LdapGroup,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "action_definitions")]
#[oai(rename = "ActionDefinition")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub kind: ActionKind,
    /// Set on `Grant` rows only — the `Remove` action that undoes it. A `Grant`
    /// can't be attached to a policy without this being set (see `warpgate-actions`).
    pub paired_action_id: Option<Uuid>,
    pub connector_type: ConnectorType,
    /// Connector-specific parameters — e.g. for `LdapGroup`: `ldap_server_id`,
    /// `group_dn`, `member_dn_template` (with a `{username}` placeholder).
    pub config: serde_json::Value,
    /// If true, a failure of this action doesn't block the session (Grant) or
    /// isn't retried forever (Remove) — it's just logged.
    pub continue_on_error: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

/// Which `Grant` action(s) an `access_policy` triggers when it authorizes a session.
/// The matching `Remove` (via `ActionDefinition::paired_action_id`) is scheduled
/// automatically once the Grant succeeds — it isn't listed here separately.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "access_policy_actions")]
#[oai(rename = "AccessPolicyAction")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub access_policy_id: Uuid,
    pub action_definition_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

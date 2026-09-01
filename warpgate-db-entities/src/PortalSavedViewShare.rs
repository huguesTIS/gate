use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// One sharing grant on a `PortalSavedView`, to a group or to a single user. See
/// `ARCHITECTURE_TECHNIQUE.md` §13 — a shared view is a read-only lens over the
/// recipient's own `access_policies`, never an authorization shortcut. Exactly one
/// of `shared_with_user_group_id`/`shared_with_user_id` is set; validated at the API
/// layer, not a DB constraint.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "portal_saved_view_shares")]
#[oai(rename = "PortalSavedViewShare")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub saved_view_id: Uuid,
    pub shared_with_user_group_id: Option<Uuid>,
    pub shared_with_user_id: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

/// A manually-pinned target within a `PortalSavedView`. See
/// `ARCHITECTURE_TECHNIQUE.md` §13 — a view's manual list and its `filter_json`
/// combine freely; this table only ever holds the manual half.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "portal_saved_view_targets")]
#[oai(rename = "PortalSavedViewTarget")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub saved_view_id: Uuid,
    pub target_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

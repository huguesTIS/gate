use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// A bookmarked filter+selection combo in `warpgate-web-portal`'s sidebar. See
/// `ARCHITECTURE_TECHNIQUE.md` §13 — `filter_json` is an intentionally open schema
/// (no fixed categories), combinable with manually-pinned targets
/// (`PortalSavedViewTarget`); either half may be empty. Distinct from
/// `PortalFavorite` (a lighter single-target star toggle).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "portal_saved_views")]
#[oai(rename = "PortalSavedView")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub filter_json: Option<serde_json::Value>,
    pub position: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

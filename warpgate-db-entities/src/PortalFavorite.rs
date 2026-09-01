use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// A user's starred target in `warpgate-web-portal`'s sidebar. See
/// `ARCHITECTURE_TECHNIQUE.md` §13 — distinct from and lighter-weight than saved
/// views: a single per-row toggle, no filter/selection state attached.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "portal_favorites")]
#[oai(rename = "PortalFavorite")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

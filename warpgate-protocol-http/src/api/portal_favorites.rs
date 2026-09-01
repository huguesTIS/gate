use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::PortalFavorite;

use crate::api::auth_scheme::AuthedSession;

pub struct Api;

#[derive(ApiResponse)]
enum GetFavoritesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<Uuid>>),
}

#[derive(ApiResponse)]
enum AddFavoriteResponse {
    #[oai(status = 204)]
    Added,
}

#[derive(ApiResponse)]
enum RemoveFavoriteResponse {
    #[oai(status = 204)]
    Removed,
}

#[OpenApi]
impl Api {
    #[oai(path = "/favorites", method = "get", operation_id = "get_favorites")]
    async fn api_get_favorites(
        &self,
        ctx: AuthedSession,
    ) -> Result<GetFavoritesResponse, WarpgateError> {
        let db = &ctx.services().db;
        let favorites = PortalFavorite::Entity::find()
            .filter(PortalFavorite::Column::UserId.eq(ctx.auth.user_id()))
            .all(db)
            .await?;
        Ok(GetFavoritesResponse::Ok(Json(
            favorites.into_iter().map(|f| f.target_id).collect(),
        )))
    }

    #[oai(
        path = "/favorites/:target_id",
        method = "put",
        operation_id = "add_favorite"
    )]
    async fn api_add_favorite(
        &self,
        ctx: AuthedSession,
        target_id: Path<Uuid>,
    ) -> Result<AddFavoriteResponse, WarpgateError> {
        let db = &ctx.services().db;
        let user_id = ctx.auth.user_id();
        let target_id = *target_id;

        let existing = PortalFavorite::Entity::find()
            .filter(PortalFavorite::Column::UserId.eq(user_id))
            .filter(PortalFavorite::Column::TargetId.eq(target_id))
            .one(db)
            .await?;

        if existing.is_none() {
            PortalFavorite::ActiveModel {
                id: sea_orm::ActiveValue::NotSet,
                user_id: Set(user_id),
                target_id: Set(target_id),
                created_at: Set(OffsetDateTime::now_utc()),
            }
            .insert(db)
            .await?;
        }

        Ok(AddFavoriteResponse::Added)
    }

    #[oai(
        path = "/favorites/:target_id",
        method = "delete",
        operation_id = "remove_favorite"
    )]
    async fn api_remove_favorite(
        &self,
        ctx: AuthedSession,
        target_id: Path<Uuid>,
    ) -> Result<RemoveFavoriteResponse, WarpgateError> {
        let db = &ctx.services().db;
        PortalFavorite::Entity::delete_many()
            .filter(PortalFavorite::Column::UserId.eq(ctx.auth.user_id()))
            .filter(PortalFavorite::Column::TargetId.eq(*target_id))
            .exec(db)
            .await?;

        Ok(RemoveFavoriteResponse::Removed)
    }
}

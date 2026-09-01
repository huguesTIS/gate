use std::collections::HashMap;

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{PortalSavedView, PortalSavedViewShare, PortalSavedViewTarget, UserGroupMember};

use crate::api::auth_scheme::AuthedSession;

pub struct Api;

#[derive(Object)]
struct SavedViewRequest {
    name: String,
    filter_json: Option<serde_json::Value>,
    target_ids: Vec<Uuid>,
}

#[derive(Object)]
struct SavedViewResponse {
    id: Uuid,
    name: String,
    filter_json: Option<serde_json::Value>,
    target_ids: Vec<Uuid>,
    /// `false` for a view shared with the caller by someone else — read-only (see
    /// `ARCHITECTURE_TECHNIQUE.md` §13: use `duplicate` to get an editable copy).
    owned: bool,
}

#[derive(Object)]
struct ShareRequest {
    shared_with_user_group_id: Option<Uuid>,
    shared_with_user_id: Option<Uuid>,
}

#[derive(Object)]
struct ShareResponse {
    id: i32,
    shared_with_user_group_id: Option<Uuid>,
    shared_with_user_id: Option<Uuid>,
}

impl From<PortalSavedViewShare::Model> for ShareResponse {
    fn from(m: PortalSavedViewShare::Model) -> Self {
        Self {
            id: m.id,
            shared_with_user_group_id: m.shared_with_user_group_id,
            shared_with_user_id: m.shared_with_user_id,
        }
    }
}

async fn active_group_ids(
    db: &sea_orm::DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<Uuid>, WarpgateError> {
    let memberships = UserGroupMember::Entity::find_active()
        .filter(UserGroupMember::Column::UserId.eq(user_id))
        .all(db)
        .await?;
    Ok(memberships.into_iter().map(|m| m.user_group_id).collect())
}

async fn view_target_ids(
    db: &sea_orm::DatabaseConnection,
    view_id: Uuid,
) -> Result<Vec<Uuid>, WarpgateError> {
    let rows = PortalSavedViewTarget::Entity::find()
        .filter(PortalSavedViewTarget::Column::SavedViewId.eq(view_id))
        .all(db)
        .await?;
    Ok(rows.into_iter().map(|r| r.target_id).collect())
}

async fn replace_view_targets(
    db: &sea_orm::DatabaseConnection,
    view_id: Uuid,
    target_ids: &[Uuid],
) -> Result<(), WarpgateError> {
    PortalSavedViewTarget::Entity::delete_many()
        .filter(PortalSavedViewTarget::Column::SavedViewId.eq(view_id))
        .exec(db)
        .await?;
    for target_id in target_ids {
        PortalSavedViewTarget::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            saved_view_id: Set(view_id),
            target_id: Set(*target_id),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

/// A view the caller may read: owned outright, or shared with them (directly or via
/// an active group membership). Returns `(view, owned)`.
async fn visible_view(
    db: &sea_orm::DatabaseConnection,
    view_id: Uuid,
    user_id: Uuid,
) -> Result<Option<(PortalSavedView::Model, bool)>, WarpgateError> {
    let Some(view) = PortalSavedView::Entity::find_by_id(view_id).one(db).await? else {
        return Ok(None);
    };
    if view.user_id == user_id {
        return Ok(Some((view, true)));
    }

    let group_ids = active_group_ids(db, user_id).await?;
    let shared = PortalSavedViewShare::Entity::find()
        .filter(PortalSavedViewShare::Column::SavedViewId.eq(view_id))
        .filter(
            PortalSavedViewShare::Column::SharedWithUserId
                .eq(user_id)
                .or(PortalSavedViewShare::Column::SharedWithUserGroupId.is_in(group_ids)),
        )
        .one(db)
        .await?;

    Ok(shared.map(|_| (view, false)))
}

#[derive(ApiResponse)]
enum GetSavedViewsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SavedViewResponse>>),
}

#[derive(ApiResponse)]
enum CreateSavedViewResponse {
    #[oai(status = 201)]
    Created(Json<SavedViewResponse>),
}

#[derive(ApiResponse)]
enum UpdateSavedViewResponse {
    #[oai(status = 200)]
    Ok(Json<SavedViewResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteSavedViewResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DuplicateSavedViewResponse {
    #[oai(status = 201)]
    Created(Json<SavedViewResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetSharesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ShareResponse>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddShareResponse {
    #[oai(status = 201)]
    Created(Json<ShareResponse>),
    #[oai(status = 404)]
    NotFound,
    /// Neither or both of `shared_with_user_group_id`/`shared_with_user_id` were set.
    #[oai(status = 422)]
    InvalidTarget,
}

#[derive(ApiResponse)]
enum RemoveShareResponse {
    #[oai(status = 204)]
    Removed,
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/saved-views",
        method = "get",
        operation_id = "get_saved_views"
    )]
    async fn api_get_saved_views(
        &self,
        ctx: AuthedSession,
    ) -> Result<GetSavedViewsResponse, WarpgateError> {
        let db = &ctx.services().db;
        let user_id = ctx.auth.user_id();

        let owned_views = PortalSavedView::Entity::find()
            .filter(PortalSavedView::Column::UserId.eq(user_id))
            .all(db)
            .await?;

        let group_ids = active_group_ids(db, user_id).await?;
        let shares = PortalSavedViewShare::Entity::find()
            .filter(
                PortalSavedViewShare::Column::SharedWithUserId
                    .eq(user_id)
                    .or(PortalSavedViewShare::Column::SharedWithUserGroupId.is_in(group_ids)),
            )
            .all(db)
            .await?;
        let shared_view_ids: Vec<Uuid> = shares.into_iter().map(|s| s.saved_view_id).collect();
        let shared_views = if shared_view_ids.is_empty() {
            vec![]
        } else {
            PortalSavedView::Entity::find()
                .filter(PortalSavedView::Column::Id.is_in(shared_view_ids))
                .filter(PortalSavedView::Column::UserId.ne(user_id))
                .all(db)
                .await?
        };

        let mut all_views: Vec<(PortalSavedView::Model, bool)> = owned_views
            .into_iter()
            .map(|v| (v, true))
            .chain(shared_views.into_iter().map(|v| (v, false)))
            .collect();
        // A view can be reachable via more than one active group; keep one copy.
        all_views.sort_by_key(|(v, _)| v.id);
        all_views.dedup_by_key(|(v, _)| v.id);

        let view_ids: Vec<Uuid> = all_views.iter().map(|(v, _)| v.id).collect();
        let target_rows = PortalSavedViewTarget::Entity::find()
            .filter(PortalSavedViewTarget::Column::SavedViewId.is_in(view_ids))
            .all(db)
            .await?;

        let mut targets_by_view: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in target_rows {
            targets_by_view
                .entry(row.saved_view_id)
                .or_default()
                .push(row.target_id);
        }

        let result = all_views
            .into_iter()
            .map(|(v, owned)| SavedViewResponse {
                target_ids: targets_by_view.remove(&v.id).unwrap_or_default(),
                id: v.id,
                name: v.name,
                filter_json: v.filter_json,
                owned,
            })
            .collect();

        Ok(GetSavedViewsResponse::Ok(Json(result)))
    }

    #[oai(
        path = "/saved-views",
        method = "post",
        operation_id = "create_saved_view"
    )]
    async fn api_create_saved_view(
        &self,
        ctx: AuthedSession,
        body: Json<SavedViewRequest>,
    ) -> Result<CreateSavedViewResponse, WarpgateError> {
        let db = &ctx.services().db;
        let now = OffsetDateTime::now_utc();
        let id = Uuid::new_v4();

        PortalSavedView::ActiveModel {
            id: Set(id),
            user_id: Set(ctx.auth.user_id()),
            name: Set(body.name.clone()),
            filter_json: Set(body.filter_json.clone()),
            position: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await?;

        replace_view_targets(db, id, &body.target_ids).await?;

        Ok(CreateSavedViewResponse::Created(Json(SavedViewResponse {
            id,
            name: body.name.clone(),
            filter_json: body.filter_json.clone(),
            target_ids: body.target_ids.clone(),
            owned: true,
        })))
    }

    #[oai(
        path = "/saved-views/:view_id",
        method = "put",
        operation_id = "update_saved_view"
    )]
    async fn api_update_saved_view(
        &self,
        ctx: AuthedSession,
        view_id: Path<Uuid>,
        body: Json<SavedViewRequest>,
    ) -> Result<UpdateSavedViewResponse, WarpgateError> {
        let db = &ctx.services().db;
        let Some(existing) = PortalSavedView::Entity::find_by_id(*view_id).one(db).await? else {
            return Ok(UpdateSavedViewResponse::NotFound);
        };
        if existing.user_id != ctx.auth.user_id() {
            return Ok(UpdateSavedViewResponse::NotFound);
        }

        let mut active: PortalSavedView::ActiveModel = existing.into();
        active.name = Set(body.name.clone());
        active.filter_json = Set(body.filter_json.clone());
        active.updated_at = Set(OffsetDateTime::now_utc());
        active.update(db).await?;

        replace_view_targets(db, *view_id, &body.target_ids).await?;

        Ok(UpdateSavedViewResponse::Ok(Json(SavedViewResponse {
            id: *view_id,
            name: body.name.clone(),
            filter_json: body.filter_json.clone(),
            target_ids: body.target_ids.clone(),
            owned: true,
        })))
    }

    #[oai(
        path = "/saved-views/:view_id",
        method = "delete",
        operation_id = "delete_saved_view"
    )]
    async fn api_delete_saved_view(
        &self,
        ctx: AuthedSession,
        view_id: Path<Uuid>,
    ) -> Result<DeleteSavedViewResponse, WarpgateError> {
        let db = &ctx.services().db;
        let Some(existing) = PortalSavedView::Entity::find_by_id(*view_id).one(db).await? else {
            return Ok(DeleteSavedViewResponse::NotFound);
        };
        if existing.user_id != ctx.auth.user_id() {
            return Ok(DeleteSavedViewResponse::NotFound);
        }

        PortalSavedViewShare::Entity::delete_many()
            .filter(PortalSavedViewShare::Column::SavedViewId.eq(*view_id))
            .exec(db)
            .await?;
        PortalSavedViewTarget::Entity::delete_many()
            .filter(PortalSavedViewTarget::Column::SavedViewId.eq(*view_id))
            .exec(db)
            .await?;
        PortalSavedView::Entity::delete_by_id(*view_id).exec(db).await?;

        Ok(DeleteSavedViewResponse::Deleted)
    }

    /// Fork a visible view (owned or shared-with-me) into a new, independently
    /// editable view owned by the caller. See `ARCHITECTURE_TECHNIQUE.md` §13: a
    /// shared view is read-only, this is how a recipient customizes their own copy.
    #[oai(
        path = "/saved-views/:view_id/duplicate",
        method = "post",
        operation_id = "duplicate_saved_view"
    )]
    async fn api_duplicate_saved_view(
        &self,
        ctx: AuthedSession,
        view_id: Path<Uuid>,
    ) -> Result<DuplicateSavedViewResponse, WarpgateError> {
        let db = &ctx.services().db;
        let user_id = ctx.auth.user_id();

        let Some((source, _owned)) = visible_view(db, *view_id, user_id).await? else {
            return Ok(DuplicateSavedViewResponse::NotFound);
        };
        let target_ids = view_target_ids(db, *view_id).await?;

        let new_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        PortalSavedView::ActiveModel {
            id: Set(new_id),
            user_id: Set(user_id),
            name: Set(format!("{} (copy)", source.name)),
            filter_json: Set(source.filter_json.clone()),
            position: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await?;
        replace_view_targets(db, new_id, &target_ids).await?;

        Ok(DuplicateSavedViewResponse::Created(Json(SavedViewResponse {
            id: new_id,
            name: format!("{} (copy)", source.name),
            filter_json: source.filter_json,
            target_ids,
            owned: true,
        })))
    }

    #[oai(
        path = "/saved-views/:view_id/shares",
        method = "get",
        operation_id = "get_saved_view_shares"
    )]
    async fn api_get_shares(
        &self,
        ctx: AuthedSession,
        view_id: Path<Uuid>,
    ) -> Result<GetSharesResponse, WarpgateError> {
        let db = &ctx.services().db;
        let Some(view) = PortalSavedView::Entity::find_by_id(*view_id).one(db).await? else {
            return Ok(GetSharesResponse::NotFound);
        };
        if view.user_id != ctx.auth.user_id() {
            return Ok(GetSharesResponse::NotFound);
        }

        let shares = PortalSavedViewShare::Entity::find()
            .filter(PortalSavedViewShare::Column::SavedViewId.eq(*view_id))
            .all(db)
            .await?;

        Ok(GetSharesResponse::Ok(Json(
            shares.into_iter().map(ShareResponse::from).collect(),
        )))
    }

    #[oai(
        path = "/saved-views/:view_id/shares",
        method = "post",
        operation_id = "add_saved_view_share"
    )]
    async fn api_add_share(
        &self,
        ctx: AuthedSession,
        view_id: Path<Uuid>,
        body: Json<ShareRequest>,
    ) -> Result<AddShareResponse, WarpgateError> {
        let db = &ctx.services().db;
        let Some(view) = PortalSavedView::Entity::find_by_id(*view_id).one(db).await? else {
            return Ok(AddShareResponse::NotFound);
        };
        if view.user_id != ctx.auth.user_id() {
            return Ok(AddShareResponse::NotFound);
        }

        let has_group = body.shared_with_user_group_id.is_some();
        let has_user = body.shared_with_user_id.is_some();
        if has_group == has_user {
            // Both set or neither set — exactly one recipient kind is required.
            return Ok(AddShareResponse::InvalidTarget);
        }

        let share = PortalSavedViewShare::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            saved_view_id: Set(*view_id),
            shared_with_user_group_id: Set(body.shared_with_user_group_id),
            shared_with_user_id: Set(body.shared_with_user_id),
            created_at: Set(OffsetDateTime::now_utc()),
        }
        .insert(db)
        .await?;

        Ok(AddShareResponse::Created(Json(share.into())))
    }

    #[oai(
        path = "/saved-views/:view_id/shares/:share_id",
        method = "delete",
        operation_id = "remove_saved_view_share"
    )]
    async fn api_remove_share(
        &self,
        ctx: AuthedSession,
        view_id: Path<Uuid>,
        share_id: Path<i32>,
    ) -> Result<RemoveShareResponse, WarpgateError> {
        let db = &ctx.services().db;
        let Some(view) = PortalSavedView::Entity::find_by_id(*view_id).one(db).await? else {
            return Ok(RemoveShareResponse::NotFound);
        };
        if view.user_id != ctx.auth.user_id() {
            return Ok(RemoveShareResponse::NotFound);
        }

        let result = PortalSavedViewShare::Entity::delete_many()
            .filter(PortalSavedViewShare::Column::Id.eq(*share_id))
            .filter(PortalSavedViewShare::Column::SavedViewId.eq(*view_id))
            .exec(db)
            .await?;

        if result.rows_affected == 0 {
            return Ok(RemoveShareResponse::NotFound);
        }
        Ok(RemoveShareResponse::Removed)
    }
}

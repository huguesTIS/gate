use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{AdminPermission, User as UserConfig, WarpgateError};
use warpgate_core::logging::AuditEvent;
use warpgate_db_entities::{User, UserGroup, UserGroupMember};

use super::AdminContext;

#[derive(Object)]
struct UserGroupDataRequest {
    name: String,
    description: Option<String>,
}

#[derive(ApiResponse)]
enum GetUserGroupsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserGroup::Model>>),
}

#[derive(ApiResponse)]
enum CreateUserGroupResponse {
    #[oai(status = 201)]
    Created(Json<UserGroup::Model>),
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/user-groups", method = "get", operation_id = "list_user_groups")]
    async fn api_list_user_groups(
        &self,
        admin: AdminContext,
    ) -> Result<GetUserGroupsResponse, WarpgateError> {
        let db = &admin.services().db;
        let groups = UserGroup::Entity::find()
            .order_by_asc(UserGroup::Column::Name)
            .all(db)
            .await?;
        Ok(GetUserGroupsResponse::Ok(Json(groups)))
    }

    #[oai(path = "/user-groups", method = "post", operation_id = "create_user_group")]
    async fn api_create_user_group(
        &self,
        admin: AdminContext,
        body: Json<UserGroupDataRequest>,
    ) -> Result<CreateUserGroupResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(CreateUserGroupResponse::BadRequest(Json("name".into())));
        }

        let db = &admin.services().db;
        let existing = UserGroup::Entity::find()
            .filter(UserGroup::Column::Name.eq(body.name.clone()))
            .one(db)
            .await?;
        if existing.is_some() {
            return Ok(CreateUserGroupResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        let group = UserGroup::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
        }
        .insert(db)
        .await?;

        AuditEvent::UserGroupCreated {
            user_group_id: group.id,
            name: group.name.clone(),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(CreateUserGroupResponse::Created(Json(group)))
    }
}

#[derive(ApiResponse)]
enum GetUserGroupResponse {
    #[oai(status = 200)]
    Ok(Json<UserGroup::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateUserGroupResponse {
    #[oai(status = 200)]
    Ok(Json<UserGroup::Model>),
    #[oai(status = 400)]
    BadRequest,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserGroupResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/user-groups/:id", method = "get", operation_id = "get_user_group")]
    async fn api_get_user_group(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetUserGroupResponse, WarpgateError> {
        let db = &admin.services().db;
        let group = UserGroup::Entity::find_by_id(id.0).one(db).await?;
        Ok(match group {
            Some(group) => GetUserGroupResponse::Ok(Json(group)),
            None => GetUserGroupResponse::NotFound,
        })
    }

    #[oai(path = "/user-groups/:id", method = "put", operation_id = "update_user_group")]
    async fn api_update_user_group(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<UserGroupDataRequest>,
    ) -> Result<UpdateUserGroupResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(UpdateUserGroupResponse::BadRequest);
        }

        let db = &admin.services().db;
        let Some(group) = UserGroup::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateUserGroupResponse::NotFound);
        };

        let existing = UserGroup::Entity::find()
            .filter(UserGroup::Column::Name.eq(body.name.clone()))
            .filter(UserGroup::Column::Id.ne(id.0))
            .one(db)
            .await?;
        if existing.is_some() {
            return Ok(UpdateUserGroupResponse::BadRequest);
        }

        let mut group: UserGroup::ActiveModel = group.into();
        group.name = Set(body.name.clone());
        group.description = Set(body.description.clone().unwrap_or_default());
        let group = group.update(db).await?;
        Ok(UpdateUserGroupResponse::Ok(Json(group)))
    }

    #[oai(
        path = "/user-groups/:id",
        method = "delete",
        operation_id = "delete_user_group"
    )]
    async fn api_delete_user_group(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteUserGroupResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(group) = UserGroup::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteUserGroupResponse::NotFound);
        };

        UserGroupMember::Entity::delete_many()
            .filter(UserGroupMember::Column::UserGroupId.eq(id.0))
            .exec(db)
            .await?;

        let name = group.name.clone();
        group.delete(db).await?;

        AuditEvent::UserGroupDeleted {
            user_group_id: id.0,
            name,
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(DeleteUserGroupResponse::Deleted)
    }
}

#[derive(ApiResponse)]
enum GetUserGroupMembersResponse {
    #[oai(status = 200)]
    // `UserConfig` (`warpgate_common::User`), not the raw `User::Model` entity: the two
    // share the OpenAPI schema name "User" and the entity was never meant to be
    // API-facing (see `users.rs`'s `GetUsersResponse` for the established pattern).
    Ok(Json<Vec<UserConfig>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(Object)]
struct AddUserGroupMemberRequest {
    /// When this membership expires (null = never) — the lever for third-party
    /// account lifecycle: set this when onboarding a tiers for a fixed term.
    expires_at: Option<OffsetDateTime>,
}

#[derive(ApiResponse)]
enum AddUserGroupMemberResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum RemoveUserGroupMemberResponse {
    #[oai(status = 204)]
    Removed,
    #[oai(status = 404)]
    NotFound,
}

pub struct MembersApi;

#[OpenApi]
impl MembersApi {
    #[oai(
        path = "/user-groups/:id/members",
        method = "get",
        operation_id = "list_user_group_members"
    )]
    async fn api_list_members(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetUserGroupMembersResponse, WarpgateError> {
        let db = &admin.services().db;
        if UserGroup::Entity::find_by_id(id.0).one(db).await?.is_none() {
            return Ok(GetUserGroupMembersResponse::NotFound);
        }

        let member_ids: Vec<Uuid> = UserGroupMember::Entity::find_active()
            .filter(UserGroupMember::Column::UserGroupId.eq(id.0))
            .all(db)
            .await?
            .into_iter()
            .map(|m| m.user_id)
            .collect();

        let mut users = Vec::new();
        for user_id in member_ids {
            if let Some(user) = User::Entity::find_by_id(user_id).one(db).await? {
                users.push(UserConfig::try_from(user)?);
            }
        }
        Ok(GetUserGroupMembersResponse::Ok(Json(users)))
    }

    #[oai(
        path = "/user-groups/:id/members/:user_id",
        method = "put",
        operation_id = "add_user_group_member"
    )]
    async fn api_add_member(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        user_id: Path<Uuid>,
        body: Json<Option<AddUserGroupMemberRequest>>,
    ) -> Result<AddUserGroupMemberResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        if UserGroup::Entity::find_by_id(id.0).one(db).await?.is_none() {
            return Ok(AddUserGroupMemberResponse::NotFound);
        }
        if User::Entity::find_by_id(user_id.0).one(db).await?.is_none() {
            return Ok(AddUserGroupMemberResponse::NotFound);
        }

        let expires_at = body.0.and_then(|b| b.expires_at);
        UserGroupMember::Entity::idempotent_grant(db, id.0, user_id.0, expires_at).await?;

        Ok(AddUserGroupMemberResponse::Created)
    }

    #[oai(
        path = "/user-groups/:id/members/:user_id",
        method = "delete",
        operation_id = "remove_user_group_member"
    )]
    async fn api_remove_member(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        user_id: Path<Uuid>,
    ) -> Result<RemoveUserGroupMemberResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(membership) = UserGroupMember::Entity::find()
            .filter(UserGroupMember::Column::UserGroupId.eq(id.0))
            .filter(UserGroupMember::Column::UserId.eq(user_id.0))
            .one(db)
            .await?
        else {
            return Ok(RemoveUserGroupMemberResponse::NotFound);
        };

        // Soft delete — sets revoked_at, mirrors user_roles' AccessRoleRevoked
        // handling (see users.rs) rather than deleting the row outright.
        let mut membership: UserGroupMember::ActiveModel = membership.into();
        membership.revoked_at = Set(Some(OffsetDateTime::now_utc()));
        membership.update(db).await?;

        Ok(RemoveUserGroupMemberResponse::Removed)
    }
}

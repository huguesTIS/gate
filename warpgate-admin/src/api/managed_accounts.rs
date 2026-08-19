use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{AdminPermission, Secret, WarpgateError};
use warpgate_core::logging::AuditEvent;
use warpgate_db_entities::ManagedAccount::ManagedAccountCredentialMode;
use warpgate_db_entities::{ManagedAccount, Target, UserGroup};
use warpgate_vault::VaultConfig;

use super::AdminContext;

#[derive(Object)]
struct ManagedAccountDataRequest {
    target_id: Uuid,
    user_group_id: Uuid,
    principal_name: String,
    credential_mode: ManagedAccountCredentialMode,
    /// OpenBao reference — not a secret value. Unusable until OpenBao is deployed
    /// (see backlog in `CLAUDE.md`); accepted here so the mapping is ready ahead of that.
    secret_ref: Option<String>,
    active: bool,
}

#[derive(ApiResponse)]
enum GetManagedAccountsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ManagedAccount::Model>>),
}

#[derive(ApiResponse)]
enum CreateManagedAccountResponse {
    #[oai(status = 201)]
    Created(Json<ManagedAccount::Model>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/managed-accounts",
        method = "get",
        operation_id = "list_managed_accounts"
    )]
    async fn api_list_managed_accounts(
        &self,
        admin: AdminContext,
    ) -> Result<GetManagedAccountsResponse, WarpgateError> {
        let db = &admin.services().db;
        let accounts = ManagedAccount::Entity::find()
            .order_by_asc(ManagedAccount::Column::PrincipalName)
            .all(db)
            .await?;
        Ok(GetManagedAccountsResponse::Ok(Json(accounts)))
    }

    #[oai(
        path = "/managed-accounts",
        method = "post",
        operation_id = "create_managed_account"
    )]
    async fn api_create_managed_account(
        &self,
        admin: AdminContext,
        body: Json<ManagedAccountDataRequest>,
    ) -> Result<CreateManagedAccountResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.principal_name.is_empty() {
            return Ok(CreateManagedAccountResponse::BadRequest(Json(
                "principal_name".into(),
            )));
        }

        let db = &admin.services().db;
        if Target::Entity::find_by_id(body.target_id)
            .one(db)
            .await?
            .is_none()
        {
            return Ok(CreateManagedAccountResponse::BadRequest(Json(
                "target_id not found".into(),
            )));
        }
        if UserGroup::Entity::find_by_id(body.user_group_id)
            .one(db)
            .await?
            .is_none()
        {
            return Ok(CreateManagedAccountResponse::BadRequest(Json(
                "user_group_id not found".into(),
            )));
        }

        let existing = ManagedAccount::Entity::find()
            .filter(ManagedAccount::Column::TargetId.eq(body.target_id))
            .filter(ManagedAccount::Column::UserGroupId.eq(body.user_group_id))
            .one(db)
            .await?;
        if existing.is_some() {
            return Ok(CreateManagedAccountResponse::Conflict(Json(
                "This user group already has a managed account on this target".into(),
            )));
        }

        let now = OffsetDateTime::now_utc();
        let account = ManagedAccount::ActiveModel {
            id: Set(Uuid::new_v4()),
            target_id: Set(body.target_id),
            user_group_id: Set(body.user_group_id),
            principal_name: Set(body.principal_name.clone()),
            credential_mode: Set(body.credential_mode),
            secret_ref: Set(body.secret_ref.clone()),
            active: Set(body.active),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await?;

        AuditEvent::ManagedAccountCreated {
            managed_account_id: account.id,
            target_id: account.target_id,
            user_group_id: account.user_group_id,
            principal_name: account.principal_name.clone(),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(CreateManagedAccountResponse::Created(Json(account)))
    }
}

#[derive(ApiResponse)]
enum GetManagedAccountResponse {
    #[oai(status = 200)]
    Ok(Json<ManagedAccount::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateManagedAccountResponse {
    #[oai(status = 200)]
    Ok(Json<ManagedAccount::Model>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteManagedAccountResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/managed-accounts/:id",
        method = "get",
        operation_id = "get_managed_account"
    )]
    async fn api_get_managed_account(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetManagedAccountResponse, WarpgateError> {
        let db = &admin.services().db;
        let account = ManagedAccount::Entity::find_by_id(id.0).one(db).await?;
        Ok(match account {
            Some(a) => GetManagedAccountResponse::Ok(Json(a)),
            None => GetManagedAccountResponse::NotFound,
        })
    }

    #[oai(
        path = "/managed-accounts/:id",
        method = "put",
        operation_id = "update_managed_account"
    )]
    async fn api_update_managed_account(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<ManagedAccountDataRequest>,
    ) -> Result<UpdateManagedAccountResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.principal_name.is_empty() {
            return Ok(UpdateManagedAccountResponse::BadRequest(Json(
                "principal_name".into(),
            )));
        }

        let db = &admin.services().db;
        let Some(account) = ManagedAccount::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateManagedAccountResponse::NotFound);
        };

        let existing = ManagedAccount::Entity::find()
            .filter(ManagedAccount::Column::TargetId.eq(body.target_id))
            .filter(ManagedAccount::Column::UserGroupId.eq(body.user_group_id))
            .filter(ManagedAccount::Column::Id.ne(id.0))
            .one(db)
            .await?;
        if existing.is_some() {
            return Ok(UpdateManagedAccountResponse::Conflict(Json(
                "This user group already has a managed account on this target".into(),
            )));
        }

        let mut account: ManagedAccount::ActiveModel = account.into();
        account.target_id = Set(body.target_id);
        account.user_group_id = Set(body.user_group_id);
        account.principal_name = Set(body.principal_name.clone());
        account.credential_mode = Set(body.credential_mode);
        account.secret_ref = Set(body.secret_ref.clone());
        account.active = Set(body.active);
        account.updated_at = Set(OffsetDateTime::now_utc());
        let account = account.update(db).await?;

        Ok(UpdateManagedAccountResponse::Ok(Json(account)))
    }

    #[oai(
        path = "/managed-accounts/:id",
        method = "delete",
        operation_id = "delete_managed_account"
    )]
    async fn api_delete_managed_account(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteManagedAccountResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(account) = ManagedAccount::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteManagedAccountResponse::NotFound);
        };

        let (target_id, user_group_id, principal_name) = (
            account.target_id,
            account.user_group_id,
            account.principal_name.clone(),
        );
        account.delete(db).await?;

        AuditEvent::ManagedAccountDeleted {
            managed_account_id: id.0,
            target_id,
            user_group_id,
            principal_name,
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(DeleteManagedAccountResponse::Deleted)
    }
}

#[derive(Object)]
struct SetManagedAccountSecretRequest {
    value: Secret<String>,
}

#[derive(ApiResponse)]
enum SetManagedAccountSecretResponse {
    #[oai(status = 204)]
    Set,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 502)]
    VaultError(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteManagedAccountSecretResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 502)]
    VaultError(Json<String>),
}

/// Sets/deletes a managed account's secret **value** in OpenBao — the value itself
/// never touches Warpgate's own DB, not even encrypted (see `ARCHITECTURE_TECHNIQUE.md`
/// §10, "`managed_accounts` — pas de secret local"). No GET here on purpose: the row's
/// `secret_ref` is meant to be consumed by Warpgate itself (connectors) at connection
/// time, not re-read by an admin through this API.
pub struct SecretApi;

#[OpenApi]
impl SecretApi {
    #[oai(
        path = "/managed-accounts/:id/secret",
        method = "put",
        operation_id = "set_managed_account_secret"
    )]
    async fn api_set_secret(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<SetManagedAccountSecretRequest>,
    ) -> Result<SetManagedAccountSecretResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(account) = ManagedAccount::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(SetManagedAccountSecretResponse::NotFound);
        };

        let vault = match VaultConfig::from_env() {
            Ok(v) => v,
            Err(err) => return Ok(SetManagedAccountSecretResponse::VaultError(Json(err.to_string()))),
        };
        let secret_ref = format!("managed-accounts/{}", account.id);
        if let Err(err) = warpgate_vault::write_secret_value(&vault, &secret_ref, &body.value).await
        {
            return Ok(SetManagedAccountSecretResponse::VaultError(Json(
                err.to_string(),
            )));
        }

        if account.secret_ref.as_deref() != Some(secret_ref.as_str()) {
            let mut account: ManagedAccount::ActiveModel = account.into();
            account.secret_ref = Set(Some(secret_ref));
            account.updated_at = Set(OffsetDateTime::now_utc());
            account.update(db).await?;
        }

        Ok(SetManagedAccountSecretResponse::Set)
    }

    #[oai(
        path = "/managed-accounts/:id/secret",
        method = "delete",
        operation_id = "delete_managed_account_secret"
    )]
    async fn api_delete_secret(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteManagedAccountSecretResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(account) = ManagedAccount::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteManagedAccountSecretResponse::NotFound);
        };
        let Some(secret_ref) = account.secret_ref.clone() else {
            return Ok(DeleteManagedAccountSecretResponse::Deleted);
        };

        let vault = match VaultConfig::from_env() {
            Ok(v) => v,
            Err(err) => {
                return Ok(DeleteManagedAccountSecretResponse::VaultError(Json(
                    err.to_string(),
                )));
            }
        };
        if let Err(err) = warpgate_vault::delete_secret(&vault, &secret_ref).await {
            return Ok(DeleteManagedAccountSecretResponse::VaultError(Json(
                err.to_string(),
            )));
        }

        let mut account: ManagedAccount::ActiveModel = account.into();
        account.secret_ref = Set(None);
        account.updated_at = Set(OffsetDateTime::now_utc());
        account.update(db).await?;

        Ok(DeleteManagedAccountSecretResponse::Deleted)
    }
}

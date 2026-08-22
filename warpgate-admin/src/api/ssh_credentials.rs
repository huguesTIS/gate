use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set};
use uuid::Uuid;
use warpgate_common::{AdminPermission, Secret, WarpgateError, externalize_secret};
use warpgate_db_entities::SshCredential;

use super::AdminContext;

/// Never carries `password` — same redact-by-omission convention as
/// `LdapServerResponse` in `ldap_servers.rs`.
#[derive(Object)]
struct SshCredentialResponse {
    id: Uuid,
    name: String,
    host: String,
    port: i32,
    username: String,
    description: String,
}

impl From<SshCredential::Model> for SshCredentialResponse {
    fn from(model: SshCredential::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            host: model.host,
            port: model.port,
            username: model.username,
            description: model.description,
        }
    }
}

#[derive(Object)]
struct CreateSshCredentialRequest {
    name: String,
    host: String,
    #[oai(default = "default_port")]
    port: i32,
    username: String,
    password: Secret<String>,
    description: Option<String>,
}

const fn default_port() -> i32 {
    22
}

#[derive(Object)]
struct UpdateSshCredentialRequest {
    name: String,
    host: String,
    port: i32,
    username: String,
    /// Omit to keep the existing (stored) password.
    password: Option<Secret<String>>,
    description: Option<String>,
}

#[derive(ApiResponse)]
enum GetSshCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SshCredentialResponse>>),
}

#[derive(ApiResponse)]
enum CreateSshCredentialResponse {
    #[oai(status = 201)]
    Created(Json<SshCredentialResponse>),
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/ssh-credentials",
        method = "get",
        operation_id = "list_ssh_credentials"
    )]
    async fn api_list_ssh_credentials(
        &self,
        admin: AdminContext,
    ) -> Result<GetSshCredentialsResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let credentials = SshCredential::Entity::find()
            .order_by_asc(SshCredential::Column::Name)
            .all(db)
            .await?;
        Ok(GetSshCredentialsResponse::Ok(Json(
            credentials.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/ssh-credentials",
        method = "post",
        operation_id = "create_ssh_credential"
    )]
    async fn api_create_ssh_credential(
        &self,
        admin: AdminContext,
        body: Json<CreateSshCredentialRequest>,
    ) -> Result<CreateSshCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(CreateSshCredentialResponse::BadRequest(Json(
                "name".into(),
            )));
        }

        let db = &admin.services().db;
        let existing = SshCredential::Entity::find()
            .filter(SshCredential::Column::Name.eq(&body.name))
            .one(db)
            .await?;
        if existing.is_some() {
            return Ok(CreateSshCredentialResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        let values = SshCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            host: Set(body.host.clone()),
            port: Set(body.port),
            username: Set(body.username.clone()),
            password: Set(externalize_secret(body.password.expose_secret()).await?),
            description: Set(body.description.clone().unwrap_or_default()),
        };
        let credential = values.insert(db).await?;

        Ok(CreateSshCredentialResponse::Created(Json(
            credential.into(),
        )))
    }
}

#[derive(ApiResponse)]
enum GetSshCredentialResponse {
    #[oai(status = 200)]
    Ok(Json<SshCredentialResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateSshCredentialResponse {
    #[oai(status = 200)]
    Ok(Json<SshCredentialResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteSshCredentialResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/ssh-credentials/:id",
        method = "get",
        operation_id = "get_ssh_credential"
    )]
    async fn api_get_ssh_credential(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetSshCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let credential = SshCredential::Entity::find_by_id(id.0).one(db).await?;
        Ok(match credential {
            Some(c) => GetSshCredentialResponse::Ok(Json(c.into())),
            None => GetSshCredentialResponse::NotFound,
        })
    }

    #[oai(
        path = "/ssh-credentials/:id",
        method = "put",
        operation_id = "update_ssh_credential"
    )]
    async fn api_update_ssh_credential(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<UpdateSshCredentialRequest>,
    ) -> Result<UpdateSshCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(UpdateSshCredentialResponse::BadRequest(Json(
                "name".into(),
            )));
        }

        let db = &admin.services().db;
        let Some(credential) = SshCredential::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateSshCredentialResponse::NotFound);
        };

        let name_taken = SshCredential::Entity::find()
            .filter(SshCredential::Column::Name.eq(&body.name))
            .filter(SshCredential::Column::Id.ne(id.0))
            .one(db)
            .await?;
        if name_taken.is_some() {
            return Ok(UpdateSshCredentialResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        let mut model: SshCredential::ActiveModel = credential.into();
        model.name = Set(body.name.clone());
        model.host = Set(body.host.clone());
        model.port = Set(body.port);
        model.username = Set(body.username.clone());
        if let Some(password) = &body.password {
            model.password = Set(externalize_secret(password.expose_secret()).await?);
        }
        model.description = Set(body.description.clone().unwrap_or_default());

        let credential = model.update(db).await?;
        Ok(UpdateSshCredentialResponse::Ok(Json(credential.into())))
    }

    #[oai(
        path = "/ssh-credentials/:id",
        method = "delete",
        operation_id = "delete_ssh_credential"
    )]
    async fn api_delete_ssh_credential(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteSshCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(credential) = SshCredential::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteSshCredentialResponse::NotFound);
        };
        credential.delete(db).await?;

        Ok(DeleteSshCredentialResponse::Deleted)
    }
}

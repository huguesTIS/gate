use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set};
use uuid::Uuid;
use warpgate_common::{AdminPermission, Secret, WarpgateError, externalize_secret};
use warpgate_db_entities::WinrmCredential;

use super::AdminContext;

/// Never carries `password` — same redact-by-omission convention as
/// `LdapServerResponse` in `ldap_servers.rs`.
#[derive(Object)]
struct WinrmCredentialResponse {
    id: Uuid,
    name: String,
    host: String,
    port: i32,
    use_tls: bool,
    username: String,
    domain: String,
    description: String,
}

impl From<WinrmCredential::Model> for WinrmCredentialResponse {
    fn from(model: WinrmCredential::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            host: model.host,
            port: model.port,
            use_tls: model.use_tls,
            username: model.username,
            domain: model.domain,
            description: model.description,
        }
    }
}

#[derive(Object)]
struct CreateWinrmCredentialRequest {
    name: String,
    host: String,
    #[oai(default = "default_port")]
    port: i32,
    #[oai(default = "default_use_tls")]
    use_tls: bool,
    username: String,
    password: Secret<String>,
    #[oai(default)]
    domain: String,
    description: Option<String>,
}

const fn default_port() -> i32 {
    5985
}

const fn default_use_tls() -> bool {
    false
}

#[derive(Object)]
struct UpdateWinrmCredentialRequest {
    name: String,
    host: String,
    port: i32,
    use_tls: bool,
    username: String,
    /// Omit to keep the existing (stored) password.
    password: Option<Secret<String>>,
    domain: String,
    description: Option<String>,
}

#[derive(ApiResponse)]
enum GetWinrmCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<WinrmCredentialResponse>>),
}

#[derive(ApiResponse)]
enum CreateWinrmCredentialResponse {
    #[oai(status = 201)]
    Created(Json<WinrmCredentialResponse>),
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/winrm-credentials",
        method = "get",
        operation_id = "list_winrm_credentials"
    )]
    async fn api_list_winrm_credentials(
        &self,
        admin: AdminContext,
    ) -> Result<GetWinrmCredentialsResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let credentials = WinrmCredential::Entity::find()
            .order_by_asc(WinrmCredential::Column::Name)
            .all(db)
            .await?;
        Ok(GetWinrmCredentialsResponse::Ok(Json(
            credentials.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/winrm-credentials",
        method = "post",
        operation_id = "create_winrm_credential"
    )]
    async fn api_create_winrm_credential(
        &self,
        admin: AdminContext,
        body: Json<CreateWinrmCredentialRequest>,
    ) -> Result<CreateWinrmCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(CreateWinrmCredentialResponse::BadRequest(Json(
                "name".into(),
            )));
        }

        let db = &admin.services().db;
        let existing = WinrmCredential::Entity::find()
            .filter(WinrmCredential::Column::Name.eq(&body.name))
            .one(db)
            .await?;
        if existing.is_some() {
            return Ok(CreateWinrmCredentialResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        let values = WinrmCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            host: Set(body.host.clone()),
            port: Set(body.port),
            use_tls: Set(body.use_tls),
            username: Set(body.username.clone()),
            password: Set(externalize_secret(body.password.expose_secret()).await?),
            domain: Set(body.domain.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
        };
        let credential = values.insert(db).await?;

        Ok(CreateWinrmCredentialResponse::Created(Json(
            credential.into(),
        )))
    }
}

#[derive(ApiResponse)]
enum GetWinrmCredentialResponse {
    #[oai(status = 200)]
    Ok(Json<WinrmCredentialResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateWinrmCredentialResponse {
    #[oai(status = 200)]
    Ok(Json<WinrmCredentialResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteWinrmCredentialResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/winrm-credentials/:id",
        method = "get",
        operation_id = "get_winrm_credential"
    )]
    async fn api_get_winrm_credential(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetWinrmCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let credential = WinrmCredential::Entity::find_by_id(id.0).one(db).await?;
        Ok(match credential {
            Some(c) => GetWinrmCredentialResponse::Ok(Json(c.into())),
            None => GetWinrmCredentialResponse::NotFound,
        })
    }

    #[oai(
        path = "/winrm-credentials/:id",
        method = "put",
        operation_id = "update_winrm_credential"
    )]
    async fn api_update_winrm_credential(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<UpdateWinrmCredentialRequest>,
    ) -> Result<UpdateWinrmCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(UpdateWinrmCredentialResponse::BadRequest(Json(
                "name".into(),
            )));
        }

        let db = &admin.services().db;
        let Some(credential) = WinrmCredential::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateWinrmCredentialResponse::NotFound);
        };

        let name_taken = WinrmCredential::Entity::find()
            .filter(WinrmCredential::Column::Name.eq(&body.name))
            .filter(WinrmCredential::Column::Id.ne(id.0))
            .one(db)
            .await?;
        if name_taken.is_some() {
            return Ok(UpdateWinrmCredentialResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        let mut model: WinrmCredential::ActiveModel = credential.into();
        model.name = Set(body.name.clone());
        model.host = Set(body.host.clone());
        model.port = Set(body.port);
        model.use_tls = Set(body.use_tls);
        model.username = Set(body.username.clone());
        if let Some(password) = &body.password {
            model.password = Set(externalize_secret(password.expose_secret()).await?);
        }
        model.domain = Set(body.domain.clone());
        model.description = Set(body.description.clone().unwrap_or_default());

        let credential = model.update(db).await?;
        Ok(UpdateWinrmCredentialResponse::Ok(Json(credential.into())))
    }

    #[oai(
        path = "/winrm-credentials/:id",
        method = "delete",
        operation_id = "delete_winrm_credential"
    )]
    async fn api_delete_winrm_credential(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteWinrmCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(credential) = WinrmCredential::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteWinrmCredentialResponse::NotFound);
        };
        credential.delete(db).await?;

        Ok(DeleteWinrmCredentialResponse::Deleted)
    }
}

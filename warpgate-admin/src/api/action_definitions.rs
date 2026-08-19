use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, EntityTrait, ModelTrait, QueryOrder};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_core::logging::AuditEvent;
use warpgate_db_entities::ActionDefinition;
use warpgate_db_entities::ActionDefinition::{ActionKind, ConnectorType};

use super::AdminContext;

#[derive(Object)]
struct ActionDefinitionDataRequest {
    name: String,
    kind: ActionKind,
    /// Required (and validated) when `kind` is `Grant` — the `Remove` action that
    /// undoes it. See `warpgate-actions::validate_grant_pairing`.
    paired_action_id: Option<Uuid>,
    connector_type: ConnectorType,
    config: serde_json::Value,
    continue_on_error: bool,
}

#[derive(ApiResponse)]
enum GetActionDefinitionsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ActionDefinition::Model>>),
}

#[derive(ApiResponse)]
enum CreateActionDefinitionResponse {
    #[oai(status = 201)]
    Created(Json<ActionDefinition::Model>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/action-definitions",
        method = "get",
        operation_id = "list_action_definitions"
    )]
    async fn api_list_action_definitions(
        &self,
        admin: AdminContext,
    ) -> Result<GetActionDefinitionsResponse, WarpgateError> {
        let db = &admin.services().db;
        let definitions = ActionDefinition::Entity::find()
            .order_by_asc(ActionDefinition::Column::Name)
            .all(db)
            .await?;
        Ok(GetActionDefinitionsResponse::Ok(Json(definitions)))
    }

    #[oai(
        path = "/action-definitions",
        method = "post",
        operation_id = "create_action_definition"
    )]
    async fn api_create_action_definition(
        &self,
        admin: AdminContext,
        body: Json<ActionDefinitionDataRequest>,
    ) -> Result<CreateActionDefinitionResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(CreateActionDefinitionResponse::BadRequest(Json(
                "name".into(),
            )));
        }

        let db = &admin.services().db;
        let candidate = ActionDefinition::Model {
            id: Uuid::new_v4(),
            name: body.name.clone(),
            kind: body.kind,
            paired_action_id: body.paired_action_id,
            connector_type: body.connector_type,
            config: body.config.clone(),
            continue_on_error: body.continue_on_error,
        };
        if let Err(err) = warpgate_actions::validate_grant_pairing(db, &candidate).await {
            return Ok(CreateActionDefinitionResponse::BadRequest(Json(
                err.to_string(),
            )));
        }

        let values: ActionDefinition::ActiveModel = candidate.into();
        let definition = values.insert(db).await?;

        AuditEvent::ActionDefinitionCreated {
            action_definition_id: definition.id,
            name: definition.name.clone(),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(CreateActionDefinitionResponse::Created(Json(definition)))
    }
}

#[derive(ApiResponse)]
enum GetActionDefinitionResponse {
    #[oai(status = 200)]
    Ok(Json<ActionDefinition::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateActionDefinitionResponse {
    #[oai(status = 200)]
    Ok(Json<ActionDefinition::Model>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteActionDefinitionResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
    /// A `Grant` still referencing this as its `Remove` counterpart blocks deletion
    /// — deleting it would leave a Grant that can never pass pairing validation again.
    #[oai(status = 409)]
    Conflict(Json<String>),
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/action-definitions/:id",
        method = "get",
        operation_id = "get_action_definition"
    )]
    async fn api_get_action_definition(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetActionDefinitionResponse, WarpgateError> {
        let db = &admin.services().db;
        let definition = ActionDefinition::Entity::find_by_id(id.0).one(db).await?;
        Ok(match definition {
            Some(d) => GetActionDefinitionResponse::Ok(Json(d)),
            None => GetActionDefinitionResponse::NotFound,
        })
    }

    #[oai(
        path = "/action-definitions/:id",
        method = "put",
        operation_id = "update_action_definition"
    )]
    async fn api_update_action_definition(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<ActionDefinitionDataRequest>,
    ) -> Result<UpdateActionDefinitionResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(UpdateActionDefinitionResponse::BadRequest(Json(
                "name".into(),
            )));
        }

        let db = &admin.services().db;
        if ActionDefinition::Entity::find_by_id(id.0)
            .one(db)
            .await?
            .is_none()
        {
            return Ok(UpdateActionDefinitionResponse::NotFound);
        }

        let candidate = ActionDefinition::Model {
            id: id.0,
            name: body.name.clone(),
            kind: body.kind,
            paired_action_id: body.paired_action_id,
            connector_type: body.connector_type,
            config: body.config.clone(),
            continue_on_error: body.continue_on_error,
        };
        if let Err(err) = warpgate_actions::validate_grant_pairing(db, &candidate).await {
            return Ok(UpdateActionDefinitionResponse::BadRequest(Json(
                err.to_string(),
            )));
        }

        let values: ActionDefinition::ActiveModel = candidate.into();
        let definition = values.update(db).await?;
        Ok(UpdateActionDefinitionResponse::Ok(Json(definition)))
    }

    #[oai(
        path = "/action-definitions/:id",
        method = "delete",
        operation_id = "delete_action_definition"
    )]
    async fn api_delete_action_definition(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteActionDefinitionResponse, WarpgateError> {
        use sea_orm::{ColumnTrait, QueryFilter};

        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(definition) = ActionDefinition::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteActionDefinitionResponse::NotFound);
        };

        let referencing_grant = ActionDefinition::Entity::find()
            .filter(ActionDefinition::Column::PairedActionId.eq(id.0))
            .one(db)
            .await?;
        if let Some(grant) = referencing_grant {
            return Ok(DeleteActionDefinitionResponse::Conflict(Json(format!(
                "Grant action '{}' is paired with this one",
                grant.name
            ))));
        }

        let name = definition.name.clone();
        definition.delete(db).await?;

        AuditEvent::ActionDefinitionDeleted {
            action_definition_id: id.0,
            name,
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(DeleteActionDefinitionResponse::Deleted)
    }
}

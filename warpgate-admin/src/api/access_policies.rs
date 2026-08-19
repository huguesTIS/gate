use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::helpers::login_template::LoginNameTemplate;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_core::logging::AuditEvent;
use warpgate_db_entities::ActionDefinition::ActionKind;
use warpgate_db_entities::{AccessPolicy, AccessPolicyAction, ActionDefinition};

use super::AdminContext;

#[derive(Object)]
struct AccessPolicyDataRequest {
    name: String,
    user_group_id: Uuid,
    target_group_id: Option<Uuid>,
    target_label_selector: Option<serde_json::Value>,
    valid_from: Option<OffsetDateTime>,
    valid_until: Option<OffsetDateTime>,
    priority: i32,
    active: bool,
    /// Effective target login name for Requester/Managed connections; `None` =
    /// portal username as-is. See `ARCHITECTURE_TECHNIQUE.md` §10 ("Mode Requester").
    login_template: Option<LoginNameTemplate>,
    /// `Grant` actions this policy triggers when it authorizes a session. Their
    /// paired `Remove` is scheduled automatically — not listed here separately.
    action_definition_ids: Vec<Uuid>,
}

#[derive(Object)]
struct AccessPolicyResponse {
    id: Uuid,
    name: String,
    user_group_id: Uuid,
    target_group_id: Option<Uuid>,
    target_label_selector: Option<serde_json::Value>,
    valid_from: Option<OffsetDateTime>,
    valid_until: Option<OffsetDateTime>,
    priority: i32,
    active: bool,
    login_template: Option<LoginNameTemplate>,
    action_definition_ids: Vec<Uuid>,
}

impl AccessPolicyResponse {
    fn new(policy: AccessPolicy::Model, action_definition_ids: Vec<Uuid>) -> Self {
        Self {
            id: policy.id,
            name: policy.name,
            user_group_id: policy.user_group_id,
            target_group_id: policy.target_group_id,
            target_label_selector: policy.target_label_selector,
            valid_from: policy.valid_from,
            valid_until: policy.valid_until,
            priority: policy.priority,
            active: policy.active,
            // A row with a malformed/legacy-shaped value is treated as unset
            // rather than failing the whole response — this field is additive.
            login_template: policy
                .login_template
                .and_then(|v| serde_json::from_value(v).ok()),
            action_definition_ids,
        }
    }
}

async fn action_ids_for_policy(
    db: &sea_orm::DatabaseConnection,
    policy_id: Uuid,
) -> Result<Vec<Uuid>, WarpgateError> {
    Ok(AccessPolicyAction::Entity::find()
        .filter(AccessPolicyAction::Column::AccessPolicyId.eq(policy_id))
        .all(db)
        .await?
        .into_iter()
        .map(|link| link.action_definition_id)
        .collect())
}

/// Every id must name an existing `Grant` action — `access_policy_actions` only
/// ever links to Grants (see `warpgate-db-entities::AccessPolicyAction`); the
/// paired Remove is implicit.
async fn validate_action_ids(
    db: &sea_orm::DatabaseConnection,
    action_definition_ids: &[Uuid],
) -> Result<(), String> {
    for action_id in action_definition_ids {
        let Ok(Some(definition)) = ActionDefinition::Entity::find_by_id(*action_id).one(db).await
        else {
            return Err(format!("Action {action_id} not found"));
        };
        if definition.kind != ActionKind::Grant {
            return Err(format!("Action '{}' is not a Grant action", definition.name));
        }
    }
    Ok(())
}

async fn sync_policy_actions(
    db: &sea_orm::DatabaseConnection,
    policy_id: Uuid,
    action_definition_ids: &[Uuid],
) -> Result<(), WarpgateError> {
    AccessPolicyAction::Entity::delete_many()
        .filter(AccessPolicyAction::Column::AccessPolicyId.eq(policy_id))
        .exec(db)
        .await?;
    for action_id in action_definition_ids {
        AccessPolicyAction::ActiveModel {
            access_policy_id: Set(policy_id),
            action_definition_id: Set(*action_id),
            ..Default::default()
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

#[derive(ApiResponse)]
enum GetAccessPoliciesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AccessPolicyResponse>>),
}

#[derive(ApiResponse)]
enum CreateAccessPolicyResponse {
    #[oai(status = 201)]
    Created(Json<AccessPolicyResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/access-policies",
        method = "get",
        operation_id = "list_access_policies"
    )]
    async fn api_list_access_policies(
        &self,
        admin: AdminContext,
    ) -> Result<GetAccessPoliciesResponse, WarpgateError> {
        let db = &admin.services().db;
        let policies = AccessPolicy::Entity::find()
            .order_by_asc(AccessPolicy::Column::Name)
            .all(db)
            .await?;

        let mut results = Vec::new();
        for policy in policies {
            let action_definition_ids = action_ids_for_policy(db, policy.id).await?;
            results.push(AccessPolicyResponse::new(policy, action_definition_ids));
        }
        Ok(GetAccessPoliciesResponse::Ok(Json(results)))
    }

    #[oai(
        path = "/access-policies",
        method = "post",
        operation_id = "create_access_policy"
    )]
    async fn api_create_access_policy(
        &self,
        admin: AdminContext,
        body: Json<AccessPolicyDataRequest>,
    ) -> Result<CreateAccessPolicyResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(CreateAccessPolicyResponse::BadRequest(Json("name".into())));
        }

        let db = &admin.services().db;
        if let Err(err) = validate_action_ids(db, &body.action_definition_ids).await {
            return Ok(CreateAccessPolicyResponse::BadRequest(Json(err)));
        }

        let policy = AccessPolicy::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            user_group_id: Set(body.user_group_id),
            target_group_id: Set(body.target_group_id),
            target_label_selector: Set(body.target_label_selector.clone()),
            valid_from: Set(body.valid_from),
            valid_until: Set(body.valid_until),
            priority: Set(body.priority),
            active: Set(body.active),
            login_template: Set(body
                .login_template
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?),
        }
        .insert(db)
        .await?;

        sync_policy_actions(db, policy.id, &body.action_definition_ids).await?;

        AuditEvent::AccessPolicyCreated {
            access_policy_id: policy.id,
            name: policy.name.clone(),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(CreateAccessPolicyResponse::Created(Json(
            AccessPolicyResponse::new(policy, body.action_definition_ids.clone()),
        )))
    }
}

#[derive(ApiResponse)]
enum GetAccessPolicyResponse {
    #[oai(status = 200)]
    Ok(Json<AccessPolicyResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateAccessPolicyResponse {
    #[oai(status = 200)]
    Ok(Json<AccessPolicyResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteAccessPolicyResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/access-policies/:id",
        method = "get",
        operation_id = "get_access_policy"
    )]
    async fn api_get_access_policy(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetAccessPolicyResponse, WarpgateError> {
        let db = &admin.services().db;
        let Some(policy) = AccessPolicy::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetAccessPolicyResponse::NotFound);
        };
        let action_definition_ids = action_ids_for_policy(db, id.0).await?;
        Ok(GetAccessPolicyResponse::Ok(Json(
            AccessPolicyResponse::new(policy, action_definition_ids),
        )))
    }

    #[oai(
        path = "/access-policies/:id",
        method = "put",
        operation_id = "update_access_policy"
    )]
    async fn api_update_access_policy(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<AccessPolicyDataRequest>,
    ) -> Result<UpdateAccessPolicyResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        if body.name.is_empty() {
            return Ok(UpdateAccessPolicyResponse::BadRequest(Json("name".into())));
        }

        let db = &admin.services().db;
        let Some(policy) = AccessPolicy::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateAccessPolicyResponse::NotFound);
        };

        if let Err(err) = validate_action_ids(db, &body.action_definition_ids).await {
            return Ok(UpdateAccessPolicyResponse::BadRequest(Json(err)));
        }

        let mut policy: AccessPolicy::ActiveModel = policy.into();
        policy.name = Set(body.name.clone());
        policy.user_group_id = Set(body.user_group_id);
        policy.target_group_id = Set(body.target_group_id);
        policy.target_label_selector = Set(body.target_label_selector.clone());
        policy.valid_from = Set(body.valid_from);
        policy.valid_until = Set(body.valid_until);
        policy.priority = Set(body.priority);
        policy.active = Set(body.active);
        policy.login_template = Set(body
            .login_template
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?);
        let policy = policy.update(db).await?;

        sync_policy_actions(db, id.0, &body.action_definition_ids).await?;

        Ok(UpdateAccessPolicyResponse::Ok(Json(
            AccessPolicyResponse::new(policy, body.action_definition_ids.clone()),
        )))
    }

    #[oai(
        path = "/access-policies/:id",
        method = "delete",
        operation_id = "delete_access_policy"
    )]
    async fn api_delete_access_policy(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteAccessPolicyResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        let Some(policy) = AccessPolicy::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteAccessPolicyResponse::NotFound);
        };

        AccessPolicyAction::Entity::delete_many()
            .filter(AccessPolicyAction::Column::AccessPolicyId.eq(id.0))
            .exec(db)
            .await?;

        let name = policy.name.clone();
        policy.delete(db).await?;

        AuditEvent::AccessPolicyDeleted {
            access_policy_id: id.0,
            name,
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(DeleteAccessPolicyResponse::Deleted)
    }
}

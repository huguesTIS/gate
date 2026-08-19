use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_db_entities::{Target, TargetLabel};

use super::AdminContext;

#[derive(Object)]
struct LabelEntry {
    key: String,
    value: String,
}

#[derive(ApiResponse)]
enum GetTargetLabelsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<LabelEntry>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum SetTargetLabelsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<LabelEntry>>),
    #[oai(status = 404)]
    NotFound,
}

pub struct LabelsApi;

#[OpenApi]
impl LabelsApi {
    #[oai(
        path = "/targets/:id/labels",
        method = "get",
        operation_id = "get_target_labels"
    )]
    async fn api_get_target_labels(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetTargetLabelsResponse, WarpgateError> {
        let db = &admin.services().db;
        if Target::Entity::find_by_id(id.0).one(db).await?.is_none() {
            return Ok(GetTargetLabelsResponse::NotFound);
        }

        let labels = TargetLabel::Entity::find()
            .filter(TargetLabel::Column::TargetId.eq(id.0))
            .all(db)
            .await?
            .into_iter()
            .map(|l| LabelEntry {
                key: l.key,
                value: l.value,
            })
            .collect();
        Ok(GetTargetLabelsResponse::Ok(Json(labels)))
    }

    /// Replace-all: the given set of labels becomes the target's complete label
    /// set — send the full list, not a delta.
    #[oai(
        path = "/targets/:id/labels",
        method = "put",
        operation_id = "set_target_labels"
    )]
    async fn api_set_target_labels(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<Vec<LabelEntry>>,
    ) -> Result<SetTargetLabelsResponse, WarpgateError> {
        admin.require(AdminPermission::GovernanceManage)?;

        let db = &admin.services().db;
        if Target::Entity::find_by_id(id.0).one(db).await?.is_none() {
            return Ok(SetTargetLabelsResponse::NotFound);
        }

        TargetLabel::Entity::delete_many()
            .filter(TargetLabel::Column::TargetId.eq(id.0))
            .exec(db)
            .await?;

        let mut result = Vec::new();
        for entry in body.0 {
            TargetLabel::ActiveModel {
                target_id: Set(id.0),
                key: Set(entry.key.clone()),
                value: Set(entry.value.clone()),
                ..Default::default()
            }
            .insert(db)
            .await?;
            result.push(entry);
        }

        Ok(SetTargetLabelsResponse::Ok(Json(result)))
    }
}

use std::collections::HashSet;

use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
use warpgate_core::ConfigProvider;
use warpgate_db_entities::TargetLabel;

use crate::api::auth_scheme::AuthedSession;

pub struct Api;

/// One `target_labels` row, scoped to targets the caller is authorized to see —
/// same filtering as `GET /targets` (`targets_list.rs`), composed here instead of
/// editing that file (see ARCHITECTURE_TECHNIQUE.md §13, "Panneau latéral" — labels
/// aren't returned by that endpoint on purpose, kept out of the file upstream
/// actively develops).
#[derive(Object)]
struct TargetLabelSnapshot {
    target_id: Uuid,
    key: String,
    value: String,
}

#[derive(ApiResponse)]
enum GetTargetLabelsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetLabelSnapshot>>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/target-labels",
        method = "get",
        operation_id = "get_target_labels"
    )]
    async fn api_get_target_labels(
        &self,
        ctx: AuthedSession,
    ) -> Result<GetTargetLabelsResponse, WarpgateError> {
        let services = ctx.services();
        let db = &services.db;

        let authorized_ids: HashSet<Uuid> = match &ctx.auth {
            RequestAuthorization::Session(SessionAuthorization::Ticket { target_id, .. }) => {
                HashSet::from([*target_id])
            }
            RequestAuthorization::AdminToken => HashSet::new(),
            auth => {
                services
                    .config_provider
                    .authorized_target_ids(auth.user_id())
                    .await?
            }
        };

        if authorized_ids.is_empty() {
            return Ok(GetTargetLabelsResponse::Ok(Json(vec![])));
        }

        let labels = TargetLabel::Entity::find()
            .filter(TargetLabel::Column::TargetId.is_in(authorized_ids))
            .all(db)
            .await?;

        Ok(GetTargetLabelsResponse::Ok(Json(
            labels
                .into_iter()
                .map(|l| TargetLabelSnapshot {
                    target_id: l.target_id,
                    key: l.key,
                    value: l.value,
                })
                .collect(),
        )))
    }
}

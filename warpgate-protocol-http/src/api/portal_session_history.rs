use std::collections::HashSet;

use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{Recording, Session};

use crate::api::auth_scheme::AuthedSession;

pub struct Api;

const MAX_HISTORY_ENTRIES: u64 = 100;

/// One past session of the caller's own — distinct from the admin session console
/// (`warpgate-admin/src/api/sessions_list.rs`, `AdminPermission::SessionsView`-gated,
/// exposes every user's sessions plus the full `Target` config). This is scoped to
/// `user_id = caller` and returns only what's useful for self-review: target name
/// (parsed out of the redacted `target_snapshot` JSON already stored per session, so
/// it survives the target being renamed or deleted later), protocol, timing, and
/// whether a recording exists — not a link to play it back, that's a separate,
/// not-yet-built feature (see ARCHITECTURE_TECHNIQUE.md §13).
#[derive(Object)]
struct SessionHistoryEntry {
    id: Uuid,
    target_name: Option<String>,
    protocol: String,
    started: OffsetDateTime,
    ended: Option<OffsetDateTime>,
    has_recording: bool,
}

#[derive(ApiResponse)]
enum GetMySessionsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SessionHistoryEntry>>),
}

fn target_name_from_snapshot(snapshot: Option<&str>) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(snapshot?).ok()?;
    value.get("name")?.as_str().map(str::to_owned)
}

#[OpenApi]
impl Api {
    #[oai(path = "/my-sessions", method = "get", operation_id = "get_my_sessions")]
    async fn api_get_my_sessions(
        &self,
        ctx: AuthedSession,
    ) -> Result<GetMySessionsResponse, WarpgateError> {
        let db = &ctx.services().db;

        let sessions = Session::Entity::find()
            .filter(Session::Column::UserId.eq(ctx.auth.user_id()))
            .order_by_desc(Session::Column::Started)
            .limit(MAX_HISTORY_ENTRIES)
            .all(db)
            .await?;

        let session_ids: Vec<Uuid> = sessions.iter().map(|s| s.id).collect();
        let recorded_session_ids: HashSet<Uuid> = Recording::Entity::find()
            .filter(Recording::Column::SessionId.is_in(session_ids))
            .all(db)
            .await?
            .into_iter()
            .map(|r| r.session_id)
            .collect();

        let result = sessions
            .into_iter()
            .map(|s| SessionHistoryEntry {
                has_recording: recorded_session_ids.contains(&s.id),
                target_name: target_name_from_snapshot(s.target_snapshot.as_deref()),
                id: s.id,
                protocol: s.protocol,
                started: s.started,
                ended: s.ended,
            })
            .collect();

        Ok(GetMySessionsResponse::Ok(Json(result)))
    }
}

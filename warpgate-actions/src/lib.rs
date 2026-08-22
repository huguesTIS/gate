//! Grant/Remove action engine — see `ARCHITECTURE_TECHNIQUE.md` §07.
//!
//! A Pre-Session (`Grant`) action runs synchronously before a session is allowed to
//! open (called from `warpgate-core`'s `set_target()` hook); on success it schedules
//! its paired Post-Session (`Remove`) action right away, so the cleanup is durable
//! even if the process crashes before the session ever ends. A background worker
//! (`process_pending_actions`, plus `recover_stuck_executions` at startup) is the
//! backstop that guarantees the `Remove` eventually runs; `run_post_session_actions_now`
//! is just a best-effort nudge to run it immediately when a session actually ends.

mod connectors;

use std::collections::HashSet;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
};
use serde_json::json;
use time::OffsetDateTime;
use tracing::{Instrument, error, info_span, warn};
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{
    AccessPolicyAction, ActionDefinition, ActionExecution,
    ActionDefinition::{ActionKind, ConnectorType},
    ActionExecution::{ExecutionPhase, ExecutionStatus},
};

/// A `Remove` action can be retried at most this many times before being given up
/// on and marked `Failed` — a leaked grant that never gets cleaned up is a real
/// security concern, so this is logged loudly, not silently dropped.
const MAX_REMOVE_ATTEMPTS: i32 = 5;

/// A `Grant` action definition must name a `Remove` counterpart that exists —
/// checked before it's attached to any policy. See `ARCHITECTURE_TECHNIQUE.md` §07:
/// this is enforced in application code (not a DB constraint, unlike Vauban's
/// separation-of-duties `CHECK` — a cross-row existence+kind check isn't
/// expressible as a plain SQLite/Postgres/MySQL `CHECK` without triggers, which
/// would triple the maintenance surface for an MVP).
pub async fn validate_grant_pairing(
    db: &DatabaseConnection,
    definition: &ActionDefinition::Model,
) -> Result<(), WarpgateError> {
    if definition.kind != ActionKind::Grant {
        return Ok(());
    }
    let Some(paired_id) = definition.paired_action_id else {
        return Err(WarpgateError::InconsistentState(format!(
            "Grant action '{}' has no paired Remove action",
            definition.name
        )));
    };
    let Some(paired) = ActionDefinition::Entity::find_by_id(paired_id).one(db).await? else {
        return Err(WarpgateError::InconsistentState(format!(
            "Grant action '{}' points to a paired action that doesn't exist",
            definition.name
        )));
    };
    if paired.kind != ActionKind::Remove {
        return Err(WarpgateError::InconsistentState(format!(
            "Grant action '{}' is paired with '{}', which isn't a Remove action",
            definition.name, paired.name
        )));
    }
    Ok(())
}

/// Reports one action's outcome to the audit console. `warpgate-core` already depends on
/// `warpgate-actions` (for the `set_target()`/`remove_session()` hooks), so the reverse
/// dependency needed to call `AuditEvent::emit()` directly would be circular. No new
/// indirection is needed to route around it, though: `warpgate-core`'s `ValuesLogLayer`
/// (see `warpgate-core/src/logging/layer.rs`) captures *any* tracing event whose target is
/// `"audit"` (or starts with `"warpgate"`) into the persisted `log` table — it keys on the
/// tracing target string, not on the `AuditEvent` Rust type, so emitting the same shape of
/// event directly here (this crate already depends on `tracing`) reaches the console exactly
/// like every `AuditEvent::emit()` call does.
fn emit_action_audit_event(
    definition: &ActionDefinition::Model,
    phase: ExecutionPhase,
    session_id: Uuid,
    username: &str,
    success: bool,
    error: Option<&str>,
) {
    tracing::info!(
        target: "audit",
        _type = "ActionExecuted1",
        action_definition_id = %definition.id,
        action_name = %definition.name,
        connector_type = ?definition.connector_type,
        phase = ?phase,
        session_id = %session_id,
        username = %username,
        success = success,
        error = ?error,
        "Ran action"
    );
}

async fn run_connector(
    db: &DatabaseConnection,
    definition: &ActionDefinition::Model,
    username: &str,
    is_grant: bool,
) -> Result<(), WarpgateError> {
    match definition.connector_type {
        ConnectorType::LdapGroup => {
            if is_grant {
                connectors::ldap_group::grant(db, &definition.config, username).await
            } else {
                connectors::ldap_group::remove(db, &definition.config, username).await
            }
        }
        ConnectorType::SshCommand => {
            if is_grant {
                connectors::ssh_command::grant(db, &definition.config, username).await
            } else {
                connectors::ssh_command::remove(db, &definition.config, username).await
            }
        }
    }
}

/// Runs all `Grant` actions attached (via `access_policy_actions`) to any policy
/// that authorizes `user_id` for `target_id`. Meant to be called from
/// `WarpgateServerHandle::set_target()` — a returned `Err` should abort session
/// setup (a `Grant` with `continue_on_error = false` that fails does exactly that).
///
/// On success, each Grant's paired `Remove` is immediately scheduled (`Pending`)
/// for `run_post_session_actions_now`/`process_pending_actions` to pick up later.
pub async fn run_pre_session_actions(
    db: &DatabaseConnection,
    session_id: Uuid,
    user_id: Uuid,
    target_id: Uuid,
    username: &str,
) -> Result<(), WarpgateError> {
    let policies = warpgate_access::authorizing_policies(db, user_id, target_id).await?;
    if policies.is_empty() {
        return Ok(());
    }

    let policy_ids: Vec<Uuid> = policies.iter().map(|p| p.id).collect();
    let mut action_ids: HashSet<Uuid> = HashSet::new();
    for link in AccessPolicyAction::Entity::find()
        .filter(AccessPolicyAction::Column::AccessPolicyId.is_in(policy_ids))
        .all(db)
        .await?
    {
        action_ids.insert(link.action_definition_id);
    }

    for action_id in action_ids {
        let Some(definition) = ActionDefinition::Entity::find_by_id(action_id).one(db).await?
        else {
            continue;
        };
        if definition.kind != ActionKind::Grant {
            continue;
        }
        validate_grant_pairing(db, &definition).await?;

        let now = OffsetDateTime::now_utc();
        let context = json!({ "username": username });
        let execution = ActionExecution::ActiveModel {
            id: Set(Uuid::new_v4()),
            session_id: Set(session_id),
            action_definition_id: Set(definition.id),
            phase: Set(ExecutionPhase::PreSession),
            status: Set(ExecutionStatus::Running),
            context: Set(context.clone()),
            attempts: Set(1),
            last_error: Set(None),
            created_at: Set(now),
            executed_at: Set(Some(now)),
        }
        .insert(db)
        .await?;

        match run_connector(db, &definition, username, true).await {
            Ok(()) => {
                mark_execution(db, execution.id, ExecutionStatus::Succeeded, None).await?;
                emit_action_audit_event(
                    &definition,
                    ExecutionPhase::PreSession,
                    session_id,
                    username,
                    true,
                    None,
                );
                // Safe to unwrap — validate_grant_pairing above guarantees this.
                schedule_remove(db, session_id, definition.paired_action_id.unwrap(), context)
                    .await?;
            }
            Err(err) => {
                mark_execution(db, execution.id, ExecutionStatus::Failed, Some(err.to_string()))
                    .await?;
                emit_action_audit_event(
                    &definition,
                    ExecutionPhase::PreSession,
                    session_id,
                    username,
                    false,
                    Some(&err.to_string()),
                );
                if definition.continue_on_error {
                    warn!(action = %definition.name, error = %err, "Grant action failed, continuing (continue_on_error)");
                } else {
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

async fn schedule_remove(
    db: &DatabaseConnection,
    session_id: Uuid,
    remove_action_id: Uuid,
    context: serde_json::Value,
) -> Result<(), WarpgateError> {
    let now = OffsetDateTime::now_utc();
    ActionExecution::ActiveModel {
        id: Set(Uuid::new_v4()),
        session_id: Set(session_id),
        action_definition_id: Set(remove_action_id),
        phase: Set(ExecutionPhase::PostSession),
        status: Set(ExecutionStatus::Pending),
        context: Set(context),
        attempts: Set(0),
        last_error: Set(None),
        created_at: Set(now),
        executed_at: Set(None),
    }
    .insert(db)
    .await?;
    Ok(())
}

async fn mark_execution(
    db: &DatabaseConnection,
    id: Uuid,
    status: ExecutionStatus,
    last_error: Option<String>,
) -> Result<(), WarpgateError> {
    let Some(model) = ActionExecution::Entity::find_by_id(id).one(db).await? else {
        return Ok(());
    };
    let mut active: ActionExecution::ActiveModel = model.into();
    active.status = Set(status);
    active.last_error = Set(last_error);
    active.update(db).await?;
    Ok(())
}

/// Runs one `Pending` `Remove` execution row to completion, updating its status.
async fn run_one_removal(
    db: &DatabaseConnection,
    execution: ActionExecution::Model,
) -> Result<(), WarpgateError> {
    let Some(definition) = ActionDefinition::Entity::find_by_id(execution.action_definition_id)
        .one(db)
        .await?
    else {
        // The action definition itself is gone — nothing sensible to run; give up
        // rather than retry forever against a target that no longer exists.
        mark_execution(
            db,
            execution.id,
            ExecutionStatus::Failed,
            Some("action definition no longer exists".into()),
        )
        .await?;
        return Ok(());
    };

    let username = execution
        .context
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    let attempts = execution.attempts + 1;
    let mut active: ActionExecution::ActiveModel = execution.clone().into();
    active.status = Set(ExecutionStatus::Running);
    active.attempts = Set(attempts);
    active.executed_at = Set(Some(OffsetDateTime::now_utc()));
    active.update(db).await?;

    match run_connector(db, &definition, &username, false).await {
        Ok(()) => {
            mark_execution(db, execution.id, ExecutionStatus::Succeeded, None).await?;
            emit_action_audit_event(
                &definition,
                execution.phase,
                execution.session_id,
                &username,
                true,
                None,
            );
        }
        Err(err) => {
            let give_up = definition.continue_on_error || attempts >= MAX_REMOVE_ATTEMPTS;
            if give_up {
                error!(
                    action = %definition.name, session_id = %execution.session_id, error = %err, attempts,
                    "Remove action gave up — access may still be granted on the target, manual cleanup needed"
                );
            } else {
                warn!(action = %definition.name, error = %err, attempts, "Remove action failed, will retry");
            }
            // Reported on every failed attempt, not just the terminal one — an operator
            // watching the console during an incident wants to see retries happening in
            // real time, not just the eventual give-up.
            emit_action_audit_event(
                &definition,
                execution.phase,
                execution.session_id,
                &username,
                false,
                Some(&err.to_string()),
            );
            mark_execution(
                db,
                execution.id,
                if give_up { ExecutionStatus::Failed } else { ExecutionStatus::Pending },
                Some(err.to_string()),
            )
            .await?;
        }
    }
    Ok(())
}

/// Best-effort immediate processing of `session_id`'s pending `Remove` actions.
/// Meant to be called from `State::remove_session()` — errors are logged, not
/// propagated, since session teardown shouldn't block on this. The background
/// `process_pending_actions` loop is the durability backstop if this doesn't run
/// (crash) or a `Remove` fails here.
pub async fn run_post_session_actions_now(db: &DatabaseConnection, session_id: Uuid) {
    let pending = ActionExecution::Entity::find()
        .filter(ActionExecution::Column::SessionId.eq(session_id))
        .filter(ActionExecution::Column::Status.eq(ExecutionStatus::Pending))
        .filter(ActionExecution::Column::Phase.eq(ExecutionPhase::PostSession))
        .all(db)
        .await;
    let pending = match pending {
        Ok(p) => p,
        Err(err) => {
            error!(%session_id, error = %err, "Failed to look up post-session actions");
            return;
        }
    };
    for execution in pending {
        if let Err(err) = run_one_removal(db, execution).await {
            error!(%session_id, error = %err, "Failed to run post-session action");
        }
    }
}

/// Processes every `Pending` action execution regardless of session — the
/// durability backstop, meant to be polled periodically by a background loop.
///
/// Unlike `run_pre_session_actions`/`run_post_session_actions_now` (called from
/// inside a protocol session's own tracing span), this runs standalone — so each
/// execution gets its own `session=...` span here, otherwise `ValuesLogLayer`
/// (see `warpgate-core/src/logging/layer.rs`) has nothing to key a `log` row on
/// and silently drops it, same as any other session-less event.
pub async fn process_pending_actions(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let pending = ActionExecution::Entity::find()
        .filter(ActionExecution::Column::Status.eq(ExecutionStatus::Pending))
        .all(db)
        .await?;
    for execution in pending {
        let session_id = execution.session_id;
        let span = info_span!("action-retry", session = %session_id);
        run_one_removal(db, execution).instrument(span).await?;
    }
    Ok(())
}

/// Resets any `Running` execution rows back to `Pending` — meant to be called once
/// at startup, before the background loop starts. A row can only legitimately be
/// `Running` while the process that set it is alive; at startup, nothing is, so any
/// `Running` row here is evidence of a crash mid-execution.
pub async fn recover_stuck_executions(db: &DatabaseConnection) -> Result<u64, WarpgateError> {
    let stuck = ActionExecution::Entity::find()
        .filter(ActionExecution::Column::Status.eq(ExecutionStatus::Running))
        .all(db)
        .await?;
    let count = stuck.len() as u64;
    for row in stuck {
        let mut active: ActionExecution::ActiveModel = row.into();
        active.status = Set(ExecutionStatus::Pending);
        active.update(db).await?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    //! The LDAP connector itself needs a live server, so these tests cover the
    //! DB-level logic only: pairing validation and crash recovery. See
    //! `warpgate-access`'s tests for the policy-matching logic these build on.

    use sea_orm::{ConnectOptions, ConnectionTrait, Database, Schema};

    use super::*;

    async fn test_db() -> DatabaseConnection {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:"))
            .await
            .expect("connect to in-memory sqlite");
        let schema = Schema::new(sea_orm::DatabaseBackend::Sqlite);
        for stmt in [
            schema.create_table_from_entity(ActionDefinition::Entity),
            schema.create_table_from_entity(ActionExecution::Entity),
        ] {
            db.execute(db.get_database_backend().build(&stmt))
                .await
                .expect("create table");
        }
        db
    }

    async fn insert_action(
        db: &DatabaseConnection,
        kind: ActionKind,
        paired_action_id: Option<Uuid>,
    ) -> ActionDefinition::Model {
        ActionDefinition::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(format!("{kind:?}")),
            kind: Set(kind),
            paired_action_id: Set(paired_action_id),
            connector_type: Set(ConnectorType::LdapGroup),
            config: Set(json!({})),
            continue_on_error: Set(false),
        }
        .insert(db)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn grant_without_pairing_is_rejected() {
        let db = test_db().await;
        let grant = insert_action(&db, ActionKind::Grant, None).await;
        assert!(validate_grant_pairing(&db, &grant).await.is_err());
    }

    #[tokio::test]
    async fn grant_paired_with_another_grant_is_rejected() {
        let db = test_db().await;
        let other_grant = insert_action(&db, ActionKind::Grant, None).await;
        let grant = insert_action(&db, ActionKind::Grant, Some(other_grant.id)).await;
        assert!(validate_grant_pairing(&db, &grant).await.is_err());
    }

    #[tokio::test]
    async fn grant_paired_with_a_real_remove_is_accepted() {
        let db = test_db().await;
        let remove = insert_action(&db, ActionKind::Remove, None).await;
        let grant = insert_action(&db, ActionKind::Grant, Some(remove.id)).await;
        assert!(validate_grant_pairing(&db, &grant).await.is_ok());
    }

    #[tokio::test]
    async fn remove_actions_need_no_pairing() {
        let db = test_db().await;
        let remove = insert_action(&db, ActionKind::Remove, None).await;
        assert!(validate_grant_pairing(&db, &remove).await.is_ok());
    }

    #[tokio::test]
    async fn stuck_running_executions_are_reset_to_pending_at_startup() {
        let db = test_db().await;
        let definition = insert_action(&db, ActionKind::Remove, None).await;
        let now = OffsetDateTime::now_utc();
        let stuck = ActionExecution::ActiveModel {
            id: Set(Uuid::new_v4()),
            session_id: Set(Uuid::new_v4()),
            action_definition_id: Set(definition.id),
            phase: Set(ExecutionPhase::PostSession),
            status: Set(ExecutionStatus::Running),
            context: Set(json!({})),
            attempts: Set(1),
            last_error: Set(None),
            created_at: Set(now),
            executed_at: Set(Some(now)),
        }
        .insert(&db)
        .await
        .unwrap();

        let recovered = recover_stuck_executions(&db).await.unwrap();
        assert_eq!(recovered, 1);

        let reloaded = ActionExecution::Entity::find_by_id(stuck.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, ExecutionStatus::Pending);
    }
}

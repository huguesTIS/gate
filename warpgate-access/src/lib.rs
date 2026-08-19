//! RBAC evaluation for the `access_policies` model — see `ARCHITECTURE_TECHNIQUE.md` §06.
//!
//! A user is authorized for a target when at least one `access_policy` applies: the
//! policy is active and inside its validity window, the user belongs to its
//! `user_group_id`, and the target either belongs to the policy's `target_group_id`
//! or matches its `target_label_selector`.

use std::collections::HashSet;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Deserialize;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::{AccessPolicy, Target, TargetLabel, UserGroupMember};

#[derive(Debug, Clone, Deserialize)]
struct LabelSelectorEntry {
    key: String,
    value: String,
}

/// Active, in-window policies whose `user_group_id` the given user belongs to.
async fn applicable_policies(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<AccessPolicy::Model>, WarpgateError> {
    let user_group_ids: Vec<Uuid> = UserGroupMember::Entity::find_active()
        .filter(UserGroupMember::Column::UserId.eq(user_id))
        .all(db)
        .await?
        .into_iter()
        .map(|m| m.user_group_id)
        .collect();

    if user_group_ids.is_empty() {
        return Ok(vec![]);
    }

    let policies = AccessPolicy::Entity::find()
        .filter(AccessPolicy::Column::UserGroupId.is_in(user_group_ids))
        .all(db)
        .await?
        .into_iter()
        .filter(AccessPolicy::Model::in_effect)
        .collect();
    Ok(policies)
}

/// Whether `target_id` (with its resolved `target_group_id`, i.e. `Target::group_id`)
/// matches `policy`'s target selector(s) — group match OR label match, either is enough.
async fn target_matches_policy(
    db: &DatabaseConnection,
    policy: &AccessPolicy::Model,
    target_id: Uuid,
    target_group_id: Option<Uuid>,
) -> Result<bool, WarpgateError> {
    if let (Some(policy_group), Some(target_group)) = (policy.target_group_id, target_group_id)
        && policy_group == target_group
    {
        return Ok(true);
    }

    if let Some(selector) = &policy.target_label_selector {
        let entries: Vec<LabelSelectorEntry> = serde_json::from_value(selector.clone())?;
        if !entries.is_empty() {
            let labels = TargetLabel::Entity::find()
                .filter(TargetLabel::Column::TargetId.eq(target_id))
                .all(db)
                .await?;
            let all_match = entries
                .iter()
                .all(|entry| labels.iter().any(|l| l.key == entry.key && l.value == entry.value));
            if all_match {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// The `access_policies` that actually authorize `user_id` for `target_id` — not just
/// ones matching the user's groups, but ones whose target selector also matches.
///
/// Exposed so `warpgate-actions` can look up which Grant actions a policy that just
/// authorized a session should trigger, without re-deriving this matching logic.
pub async fn authorizing_policies(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<Vec<AccessPolicy::Model>, WarpgateError> {
    let Some(target) = Target::Entity::find_by_id(target_id).one(db).await? else {
        return Ok(vec![]);
    };

    let mut result = vec![];
    for policy in applicable_policies(db, user_id).await? {
        if target_matches_policy(db, &policy, target_id, target.group_id).await? {
            result.push(policy);
        }
    }
    Ok(result)
}

/// Is `user_id` authorized for `target_id`, per the `access_policies` model?
///
/// This is meant to be OR-ed with the legacy `Role`-based check during the
/// migration window — see `DatabaseConfigProvider::authorize_target_by_id`.
pub async fn is_authorized(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<bool, WarpgateError> {
    Ok(!authorizing_policies(db, user_id, target_id).await?.is_empty())
}

/// All target IDs `user_id` can reach via the `access_policies` model.
///
/// Meant to be unioned with the legacy `Role`-based set — see
/// `DatabaseConfigProvider::authorized_target_ids`.
pub async fn authorized_target_ids(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<HashSet<Uuid>, WarpgateError> {
    let policies = applicable_policies(db, user_id).await?;
    if policies.is_empty() {
        return Ok(HashSet::new());
    }

    let mut result = HashSet::new();
    for target in Target::Entity::find().all(db).await? {
        for policy in &policies {
            if target_matches_policy(db, policy, target.id, target.group_id).await? {
                result.insert(target.id);
                break;
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use sea_orm::{
        ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Schema,
        Set,
    };
    use serde_json::json;
    use time::{Duration, OffsetDateTime};
    use warpgate_db_entities::{AccessPolicy, Target, TargetGroup, TargetLabel, UserGroup, UserGroupMember};

    use super::*;

    /// In-memory SQLite DB with just the tables `warpgate-access` touches —
    /// no dependency on `warpgate-db-migrations`'s full history.
    async fn test_db() -> DatabaseConnection {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:"))
            .await
            .expect("connect to in-memory sqlite");
        // These tests don't create real User/Target rows for every FK target
        // (e.g. `users`) — only policy evaluation is under test here.
        db.execute_unprepared("PRAGMA foreign_keys = OFF;")
            .await
            .expect("disable FK enforcement");
        let schema = Schema::new(sea_orm::DatabaseBackend::Sqlite);
        for stmt in [
            schema.create_table_from_entity(UserGroup::Entity),
            schema.create_table_from_entity(UserGroupMember::Entity),
            schema.create_table_from_entity(TargetGroup::Entity),
            schema.create_table_from_entity(TargetLabel::Entity),
            schema.create_table_from_entity(AccessPolicy::Entity),
        ] {
            db.execute(db.get_database_backend().build(&stmt))
                .await
                .expect("create table");
        }
        // `Target` isn't in warpgate-db-entities' own migration-friendly form here,
        // so build its table directly too.
        db.execute(
            db.get_database_backend()
                .build(&schema.create_table_from_entity(Target::Entity)),
        )
        .await
        .expect("create targets table");
        db
    }

    async fn make_user_group(db: &DatabaseConnection, user_id: Uuid) -> Uuid {
        let group_id = Uuid::new_v4();
        UserGroup::ActiveModel {
            id: Set(group_id),
            name: Set("group".into()),
            description: Set(String::new()),
        }
        .insert(db)
        .await
        .unwrap();
        UserGroupMember::ActiveModel {
            user_group_id: Set(group_id),
            user_id: Set(user_id),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();
        group_id
    }

    async fn make_target(db: &DatabaseConnection, group_id: Option<Uuid>) -> Uuid {
        let target_id = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(target_id),
            name: Set("target".into()),
            description: Set(String::new()),
            kind: Set(Target::TargetKind::Ssh),
            options: Set(json!({})),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(group_id),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        target_id
    }

    #[tokio::test]
    async fn label_selector_grants_access() {
        let db = test_db().await;
        let user_id = Uuid::new_v4();
        let user_group_id = make_user_group(&db, user_id).await;
        let target_id = make_target(&db, None).await;

        TargetLabel::ActiveModel {
            target_id: Set(target_id),
            key: Set("env".into()),
            value: Set("prod".into()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        AccessPolicy::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("prod-access".into()),
            user_group_id: Set(user_group_id),
            target_group_id: Set(None),
            target_label_selector: Set(Some(json!([{"key": "env", "value": "prod"}]))),
            valid_from: Set(None),
            valid_until: Set(None),
            priority: Set(0),
            active: Set(true),
        }
        .insert(&db)
        .await
        .unwrap();

        assert!(is_authorized(&db, user_id, target_id).await.unwrap());
        assert_eq!(
            authorized_target_ids(&db, user_id).await.unwrap(),
            [target_id].into_iter().collect()
        );
    }

    #[tokio::test]
    async fn expired_policy_denies_access() {
        let db = test_db().await;
        let user_id = Uuid::new_v4();
        let user_group_id = make_user_group(&db, user_id).await;
        let target_id = make_target(&db, None).await;

        TargetLabel::ActiveModel {
            target_id: Set(target_id),
            key: Set("env".into()),
            value: Set("prod".into()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        AccessPolicy::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("expired".into()),
            user_group_id: Set(user_group_id),
            target_group_id: Set(None),
            target_label_selector: Set(Some(json!([{"key": "env", "value": "prod"}]))),
            valid_from: Set(None),
            valid_until: Set(Some(OffsetDateTime::now_utc() - Duration::days(1))),
            priority: Set(0),
            active: Set(true),
        }
        .insert(&db)
        .await
        .unwrap();

        assert!(!is_authorized(&db, user_id, target_id).await.unwrap());
    }

    #[tokio::test]
    async fn unrelated_user_is_denied() {
        let db = test_db().await;
        let owner_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let user_group_id = make_user_group(&db, owner_id).await;
        let target_id = make_target(&db, None).await;

        AccessPolicy::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("owner-only".into()),
            user_group_id: Set(user_group_id),
            target_group_id: Set(None),
            target_label_selector: Set(Some(json!([{"key": "env", "value": "prod"}]))),
            valid_from: Set(None),
            valid_until: Set(None),
            priority: Set(0),
            active: Set(true),
        }
        .insert(&db)
        .await
        .unwrap();

        assert!(!is_authorized(&db, other_id, target_id).await.unwrap());
    }

    #[tokio::test]
    async fn target_group_match_grants_access() {
        let db = test_db().await;
        let user_id = Uuid::new_v4();
        let user_group_id = make_user_group(&db, user_id).await;

        let target_group_id = Uuid::new_v4();
        TargetGroup::ActiveModel {
            id: Set(target_group_id),
            name: Set("prod-servers".into()),
            description: Set(String::new()),
            color: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();
        let target_id = make_target(&db, Some(target_group_id)).await;

        AccessPolicy::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("group-access".into()),
            user_group_id: Set(user_group_id),
            target_group_id: Set(Some(target_group_id)),
            target_label_selector: Set(None),
            valid_from: Set(None),
            valid_until: Set(None),
            priority: Set(0),
            active: Set(true),
        }
        .insert(&db)
        .await
        .unwrap();

        assert!(is_authorized(&db, user_id, target_id).await.unwrap());
    }
}

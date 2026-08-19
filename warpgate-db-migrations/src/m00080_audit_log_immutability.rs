use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// Makes `target = 'audit'` rows in `log` (see `warpgate-db-entities::LogEntry`)
/// append-only: `BEFORE UPDATE`/`BEFORE DELETE` triggers reject touching them
/// unless `audit_maintenance_mode.enabled` is set. The one legitimate caller
/// today is the retention purge in `warpgate-core::db::cleanup_db`, which flips
/// the flag for the duration of its own transaction. See
/// `ARCHITECTURE_TECHNIQUE.md` §04 / `warpgate-db-entities::AuditMaintenanceMode`.
///
/// Trigger SQL is backend-specific (SQLite/Postgres/MySQL) — `sea-orm-migration`
/// has no portable trigger builder, unlike table/index DDL.

pub mod audit_maintenance_mode {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "audit_maintenance_mode")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i32,
        pub enabled: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseBackend};

        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(
                audit_maintenance_mode::Entity,
            ))
            .await?;

        let conn = manager.get_connection();
        audit_maintenance_mode::ActiveModel {
            id: Set(1),
            enabled: Set(false),
        }
        .insert(conn)
        .await?;

        match manager.get_database_backend() {
            DatabaseBackend::Sqlite => {
                conn.execute_unprepared(
                    "CREATE TRIGGER audit_log_protect_update
                     BEFORE UPDATE ON log
                     FOR EACH ROW
                     WHEN OLD.target = 'audit'
                         AND (SELECT enabled FROM audit_maintenance_mode WHERE id = 1) = 0
                     BEGIN
                         SELECT RAISE(ABORT, 'audit log entries are append-only');
                     END;",
                )
                .await?;
                conn.execute_unprepared(
                    "CREATE TRIGGER audit_log_protect_delete
                     BEFORE DELETE ON log
                     FOR EACH ROW
                     WHEN OLD.target = 'audit'
                         AND (SELECT enabled FROM audit_maintenance_mode WHERE id = 1) = 0
                     BEGIN
                         SELECT RAISE(ABORT, 'audit log entries are append-only');
                     END;",
                )
                .await?;
            }
            DatabaseBackend::Postgres => {
                conn.execute_unprepared(
                    "CREATE OR REPLACE FUNCTION audit_log_protect() RETURNS TRIGGER AS $$
                     BEGIN
                         IF OLD.target = 'audit'
                             AND NOT (SELECT enabled FROM audit_maintenance_mode WHERE id = 1)
                         THEN
                             RAISE EXCEPTION 'audit log entries are append-only';
                         END IF;
                         RETURN OLD;
                     END;
                     $$ LANGUAGE plpgsql;",
                )
                .await?;
                conn.execute_unprepared(
                    "CREATE TRIGGER audit_log_protect_update
                     BEFORE UPDATE ON log
                     FOR EACH ROW EXECUTE FUNCTION audit_log_protect();",
                )
                .await?;
                conn.execute_unprepared(
                    "CREATE TRIGGER audit_log_protect_delete
                     BEFORE DELETE ON log
                     FOR EACH ROW EXECUTE FUNCTION audit_log_protect();",
                )
                .await?;
            }
            DatabaseBackend::MySql => {
                conn.execute_unprepared(
                    "CREATE TRIGGER audit_log_protect_update
                     BEFORE UPDATE ON log
                     FOR EACH ROW
                     BEGIN
                         DECLARE maint TINYINT;
                         SELECT enabled INTO maint FROM audit_maintenance_mode WHERE id = 1;
                         IF OLD.target = 'audit' AND maint = 0 THEN
                             SIGNAL SQLSTATE '45000'
                                 SET MESSAGE_TEXT = 'audit log entries are append-only';
                         END IF;
                     END;",
                )
                .await?;
                conn.execute_unprepared(
                    "CREATE TRIGGER audit_log_protect_delete
                     BEFORE DELETE ON log
                     FOR EACH ROW
                     BEGIN
                         DECLARE maint TINYINT;
                         SELECT enabled INTO maint FROM audit_maintenance_mode WHERE id = 1;
                         IF OLD.target = 'audit' AND maint = 0 THEN
                             SIGNAL SQLSTATE '45000'
                                 SET MESSAGE_TEXT = 'audit log entries are append-only';
                         END IF;
                     END;",
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use sea_orm::DatabaseBackend;

        let conn = manager.get_connection();
        conn.execute_unprepared("DROP TRIGGER audit_log_protect_update").await?;
        conn.execute_unprepared("DROP TRIGGER audit_log_protect_delete").await?;
        if matches!(manager.get_database_backend(), DatabaseBackend::Postgres) {
            conn.execute_unprepared("DROP FUNCTION IF EXISTS audit_log_protect()")
                .await?;
        }

        manager
            .drop_table(
                Table::drop()
                    .table(audit_maintenance_mode::Entity)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::sea_query::Expr;
    use sea_orm::{
        ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, QueryFilter,
    };
    use sea_orm_migration::MigratorTrait;
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_db_entities::{AuditMaintenanceMode, LogEntry};

    use crate::Migrator;

    async fn migrated_db() -> DatabaseConnection {
        warpgate_db_entities::Parameters::set_config_migration_values(
            warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
        );
        // `sqlite::memory:` is a *separate* database per connection — pin the pool
        // to one so the whole test session deterministically shares it.
        let mut opts = ConnectOptions::new("sqlite::memory:");
        opts.max_connections(1);
        let db = Database::connect(opts)
            .await
            .expect("connect to in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    async fn insert_audit_row(db: &DatabaseConnection) -> Uuid {
        use sea_orm::{ActiveValue::Set, ActiveModelTrait};

        let id = Uuid::new_v4();
        LogEntry::ActiveModel {
            id: Set(id),
            text: Set("original".into()),
            target: Set("audit".into()),
            values: Set(json!({})),
            timestamp: Set(OffsetDateTime::now_utc()),
            session_id: Set(Uuid::new_v4()),
            username: Set(None),
            related_users: Set(None),
            related_access_roles: Set(None),
            related_admin_roles: Set(None),
        }
        .insert(db)
        .await
        .expect("insert audit log row");
        id
    }

    /// Tamper attempts go through the ORM's query builder, not a raw SQL string
    /// with the UUID interpolated as text — sea-orm stores `Uuid` columns as BLOB
    /// in SQLite, so a `WHERE id = '<hyphenated-string>'` literal matches zero
    /// rows and "succeeds" vacuously without ever reaching the trigger. Confirmed
    /// with a throwaway diagnostic test before writing this comment: the trigger
    /// SQL itself was correct the whole time (also independently verified against
    /// raw `sqlite3`/`psql`/`mysql` outside any ORM) — this was a test bug, not a
    /// product bug.
    async fn try_update_text(db: &DatabaseConnection, id: Uuid) -> Result<u64, sea_orm::DbErr> {
        LogEntry::Entity::update_many()
            .col_expr(LogEntry::Column::Text, Expr::value("tampered"))
            .filter(LogEntry::Column::Id.eq(id))
            .exec(db)
            .await
            .map(|res| res.rows_affected)
    }

    async fn try_delete(db: &DatabaseConnection, id: Uuid) -> Result<u64, sea_orm::DbErr> {
        LogEntry::Entity::delete_by_id(id)
            .exec(db)
            .await
            .map(|res| res.rows_affected)
    }

    #[tokio::test]
    async fn update_is_rejected_without_maintenance_mode() {
        let db = migrated_db().await;
        let id = insert_audit_row(&db).await;

        assert!(
            try_update_text(&db, id).await.is_err(),
            "expected the trigger to reject the UPDATE"
        );
    }

    #[tokio::test]
    async fn delete_is_rejected_without_maintenance_mode() {
        let db = migrated_db().await;
        let id = insert_audit_row(&db).await;

        assert!(
            try_delete(&db, id).await.is_err(),
            "expected the trigger to reject the DELETE"
        );

        let still_there = LogEntry::Entity::find_by_id(id).one(&db).await.unwrap();
        assert!(still_there.is_some());
    }

    #[tokio::test]
    async fn delete_succeeds_once_maintenance_mode_is_enabled() {
        let db = migrated_db().await;
        let id = insert_audit_row(&db).await;

        AuditMaintenanceMode::Entity::update_many()
            .col_expr(AuditMaintenanceMode::Column::Enabled, Expr::value(true))
            .filter(AuditMaintenanceMode::Column::Id.eq(1))
            .exec(&db)
            .await
            .unwrap();

        let affected = try_delete(&db, id)
            .await
            .expect("delete should succeed with maintenance mode enabled");
        assert_eq!(affected, 1);

        let gone = LogEntry::Entity::find_by_id(id).one(&db).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn non_audit_rows_are_never_protected() {
        let db = migrated_db().await;
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        let id = Uuid::new_v4();
        LogEntry::ActiveModel {
            id: Set(id),
            text: Set("session transcript line".into()),
            target: Set("warpgate_protocol_ssh".into()),
            values: Set(json!({})),
            timestamp: Set(OffsetDateTime::now_utc()),
            session_id: Set(Uuid::new_v4()),
            username: Set(None),
            related_users: Set(None),
            related_access_roles: Set(None),
            related_admin_roles: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        let affected = try_delete(&db, id)
            .await
            .expect("non-audit rows aren't protected by the trigger");
        assert_eq!(affected, 1);
    }
}

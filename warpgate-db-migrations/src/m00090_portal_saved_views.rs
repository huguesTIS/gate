use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// `portal_saved_views` / `portal_saved_view_targets` — bookmarked filter+selection
/// combos for `warpgate-web-portal`'s sidebar (see `ARCHITECTURE_TECHNIQUE.md` §13,
/// "Onglets/vues sauvegardées"). `filter_json` is an intentionally open schema (no
/// fixed categories) so a view can be a pure filter, a pure manual target list, or
/// both combined. Sharing (`portal_saved_view_shares`) is a separate migration —
/// kept out of this one so each slice stays independently reviewable/testable.

pub mod portal_saved_view {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "portal_saved_views")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub name: String,
        pub filter_json: Option<serde_json::Value>,
        pub position: i32,
        pub created_at: OffsetDateTime,
        pub updated_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod portal_saved_view_target {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "portal_saved_view_targets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i32,
        pub saved_view_id: Uuid,
        pub target_id: Uuid,
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
        let schema = Schema::new(manager.get_database_backend());

        manager
            .create_table(schema.create_table_from_entity(portal_saved_view::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(portal_saved_view_target::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_portal_saved_views_user_id")
                    .table(portal_saved_view::Entity)
                    .col(portal_saved_view::Column::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_portal_saved_view_targets_saved_view_id")
                    .table(portal_saved_view_target::Entity)
                    .col(portal_saved_view_target::Column::SavedViewId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_portal_saved_view_targets_view_target")
                    .table(portal_saved_view_target::Entity)
                    .col(portal_saved_view_target::Column::SavedViewId)
                    .col(portal_saved_view_target::Column::TargetId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(portal_saved_view_target::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(portal_saved_view::Entity).to_owned())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_db_entities::{PortalSavedView, PortalSavedViewTarget};

    use crate::Migrator;

    async fn migrated_db() -> DatabaseConnection {
        warpgate_db_entities::Parameters::set_config_migration_values(
            warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
        );
        let mut opts = ConnectOptions::new("sqlite::memory:");
        opts.max_connections(1);
        let db = Database::connect(opts)
            .await
            .expect("connect to in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    fn new_view(user_id: Uuid, filter_json: Option<serde_json::Value>) -> PortalSavedView::ActiveModel {
        let now = OffsetDateTime::now_utc();
        PortalSavedView::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            name: Set("AD Production".into()),
            filter_json: Set(filter_json),
            position: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
        }
    }

    #[tokio::test]
    async fn a_view_can_be_a_pure_filter_with_no_manual_targets() {
        let db = migrated_db().await;
        new_view(Uuid::new_v4(), Some(json!({"kind": "Ssh", "search": "prod"})))
            .insert(&db)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_view_can_combine_a_filter_with_manually_pinned_targets() {
        let db = migrated_db().await;
        let view = new_view(Uuid::new_v4(), Some(json!({"label": {"key": "site", "value": "paris-dc1"}})))
            .insert(&db)
            .await
            .unwrap();

        PortalSavedViewTarget::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            saved_view_id: Set(view.id),
            target_id: Set(Uuid::new_v4()),
        }
        .insert(&db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_view_can_be_a_pure_manual_selection_with_no_filter() {
        let db = migrated_db().await;
        let view = new_view(Uuid::new_v4(), None).insert(&db).await.unwrap();

        for _ in 0..3 {
            PortalSavedViewTarget::ActiveModel {
                id: sea_orm::ActiveValue::NotSet,
                saved_view_id: Set(view.id),
                target_id: Set(Uuid::new_v4()),
            }
            .insert(&db)
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn the_same_target_cannot_be_pinned_twice_in_one_view() {
        let db = migrated_db().await;
        let view = new_view(Uuid::new_v4(), None).insert(&db).await.unwrap();
        let target_id = Uuid::new_v4();

        PortalSavedViewTarget::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            saved_view_id: Set(view.id),
            target_id: Set(target_id),
        }
        .insert(&db)
        .await
        .unwrap();

        let result = PortalSavedViewTarget::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            saved_view_id: Set(view.id),
            target_id: Set(target_id),
        }
        .insert(&db)
        .await;

        assert!(
            result.is_err(),
            "expected the unique (saved_view_id, target_id) constraint to reject the duplicate"
        );
    }
}

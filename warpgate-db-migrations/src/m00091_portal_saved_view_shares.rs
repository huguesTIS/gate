use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// `portal_saved_view_shares` — sharing a `PortalSavedView` with a group or a single
/// user. See `ARCHITECTURE_TECHNIQUE.md` §13, "Partage d'onglets entre utilisateurs":
/// a shared view is a read-only lens (recipients only ever see targets their own
/// `access_policies` already authorize) — never an authorization shortcut. Exactly
/// one of `shared_with_user_group_id`/`shared_with_user_id` must be set; enforced at
/// the API layer (save-time validation), not a DB constraint — same convention as
/// the Grant/Remove action pairing check (`ARCHITECTURE_TECHNIQUE.md` §04).

pub mod portal_saved_view_share {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "portal_saved_view_shares")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i32,
        pub saved_view_id: Uuid,
        pub shared_with_user_group_id: Option<Uuid>,
        pub shared_with_user_id: Option<Uuid>,
        pub created_at: OffsetDateTime,
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
            .create_table(schema.create_table_from_entity(
                portal_saved_view_share::Entity,
            ))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_portal_saved_view_shares_saved_view_id")
                    .table(portal_saved_view_share::Entity)
                    .col(portal_saved_view_share::Column::SavedViewId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_portal_saved_view_shares_group_id")
                    .table(portal_saved_view_share::Entity)
                    .col(portal_saved_view_share::Column::SharedWithUserGroupId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_portal_saved_view_shares_user_id")
                    .table(portal_saved_view_share::Entity)
                    .col(portal_saved_view_share::Column::SharedWithUserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(portal_saved_view_share::Entity)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_db_entities::{PortalSavedView, PortalSavedViewShare};

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

    async fn new_view(db: &DatabaseConnection) -> Uuid {
        let now = OffsetDateTime::now_utc();
        let id = Uuid::new_v4();
        PortalSavedView::ActiveModel {
            id: Set(id),
            user_id: Set(Uuid::new_v4()),
            name: Set("AD Production".into()),
            filter_json: Set(None),
            position: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn a_view_can_be_shared_with_a_group() {
        let db = migrated_db().await;
        let view_id = new_view(&db).await;

        PortalSavedViewShare::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            saved_view_id: Set(view_id),
            shared_with_user_group_id: Set(Some(Uuid::new_v4())),
            shared_with_user_id: Set(None),
            created_at: Set(OffsetDateTime::now_utc()),
        }
        .insert(&db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_view_can_be_shared_with_a_single_user() {
        let db = migrated_db().await;
        let view_id = new_view(&db).await;

        PortalSavedViewShare::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            saved_view_id: Set(view_id),
            shared_with_user_group_id: Set(None),
            shared_with_user_id: Set(Some(Uuid::new_v4())),
            created_at: Set(OffsetDateTime::now_utc()),
        }
        .insert(&db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_view_can_be_shared_with_several_recipients() {
        let db = migrated_db().await;
        let view_id = new_view(&db).await;

        for _ in 0..3 {
            PortalSavedViewShare::ActiveModel {
                id: sea_orm::ActiveValue::NotSet,
                saved_view_id: Set(view_id),
                shared_with_user_group_id: Set(None),
                shared_with_user_id: Set(Some(Uuid::new_v4())),
                created_at: Set(OffsetDateTime::now_utc()),
            }
            .insert(&db)
            .await
            .unwrap();
        }
    }
}

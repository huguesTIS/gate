use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// `portal_favorites` — per-user starred targets for `warpgate-web-portal`
/// (see `ARCHITECTURE_TECHNIQUE.md` §13). Plain UUID columns, not DB-enforced
/// FKs, matching every other cross-table reference in this schema (`target_labels`,
/// `user_group_members`, etc. — see `m00078_access_governance.rs`).

pub mod portal_favorite {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "portal_favorites")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i32,
        pub user_id: Uuid,
        pub target_id: Uuid,
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
            .create_table(schema.create_table_from_entity(portal_favorite::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_portal_favorites_user_id")
                    .table(portal_favorite::Entity)
                    .col(portal_favorite::Column::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_portal_favorites_user_target")
                    .table(portal_favorite::Entity)
                    .col(portal_favorite::Column::UserId)
                    .col(portal_favorite::Column::TargetId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(portal_favorite::Entity).to_owned())
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
    use warpgate_db_entities::PortalFavorite;

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

    fn new_favorite(user_id: Uuid, target_id: Uuid) -> PortalFavorite::ActiveModel {
        PortalFavorite::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            user_id: Set(user_id),
            target_id: Set(target_id),
            created_at: Set(OffsetDateTime::now_utc()),
        }
    }

    #[tokio::test]
    async fn a_user_can_favorite_a_target() {
        let db = migrated_db().await;
        new_favorite(Uuid::new_v4(), Uuid::new_v4())
            .insert(&db)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn two_users_can_each_favorite_the_same_target() {
        let db = migrated_db().await;
        let target_id = Uuid::new_v4();

        new_favorite(Uuid::new_v4(), target_id).insert(&db).await.unwrap();
        new_favorite(Uuid::new_v4(), target_id).insert(&db).await.unwrap();
    }

    #[tokio::test]
    async fn a_user_cannot_favorite_the_same_target_twice() {
        let db = migrated_db().await;
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        new_favorite(user_id, target_id).insert(&db).await.unwrap();
        let result = new_favorite(user_id, target_id).insert(&db).await;
        assert!(
            result.is_err(),
            "expected the unique (user_id, target_id) constraint to reject the duplicate"
        );
    }
}

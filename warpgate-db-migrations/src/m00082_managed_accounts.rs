use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// `managed_accounts` — identity mapping only (tiers × target × principal name),
/// never a secret value itself, not even encrypted. See `ARCHITECTURE_TECHNIQUE.md`
/// §10 ("`managed_accounts` — pas de secret local").

pub mod managed_account {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(StringLen::N(24))")]
    pub enum ManagedAccountCredentialMode {
        #[sea_orm(string_value = "vaulted_secret")]
        VaultedSecret,
        #[sea_orm(string_value = "ephemeral_certificate")]
        EphemeralCertificate,
    }

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "managed_accounts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub target_id: Uuid,
        pub user_group_id: Uuid,
        pub principal_name: String,
        pub credential_mode: ManagedAccountCredentialMode,
        pub secret_ref: Option<String>,
        pub active: bool,
        pub created_at: OffsetDateTime,
        pub updated_at: OffsetDateTime,
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
            .create_table(schema.create_table_from_entity(managed_account::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_managed_accounts_target_id")
                    .table(managed_account::Entity)
                    .col(managed_account::Column::TargetId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_managed_accounts_target_group")
                    .table(managed_account::Entity)
                    .col(managed_account::Column::TargetId)
                    .col(managed_account::Column::UserGroupId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(managed_account::Entity).to_owned())
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
    use warpgate_db_entities::ManagedAccount;
    use warpgate_db_entities::ManagedAccount::ManagedAccountCredentialMode;

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

    fn new_account(target_id: Uuid, user_group_id: Uuid) -> ManagedAccount::ActiveModel {
        let now = OffsetDateTime::now_utc();
        ManagedAccount::ActiveModel {
            id: Set(Uuid::new_v4()),
            target_id: Set(target_id),
            user_group_id: Set(user_group_id),
            principal_name: Set("svc-account".into()),
            credential_mode: Set(ManagedAccountCredentialMode::VaultedSecret),
            secret_ref: Set(None),
            active: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
        }
    }

    #[tokio::test]
    async fn one_managed_account_per_target_and_group_is_allowed() {
        let db = migrated_db().await;
        let target_id = Uuid::new_v4();
        let user_group_id = Uuid::new_v4();

        new_account(target_id, user_group_id).insert(&db).await.unwrap();
    }

    #[tokio::test]
    async fn two_groups_can_each_have_their_own_account_on_the_same_target() {
        let db = migrated_db().await;
        let target_id = Uuid::new_v4();

        new_account(target_id, Uuid::new_v4()).insert(&db).await.unwrap();
        new_account(target_id, Uuid::new_v4()).insert(&db).await.unwrap();
    }

    #[tokio::test]
    async fn a_group_cannot_have_two_managed_accounts_on_the_same_target() {
        let db = migrated_db().await;
        let target_id = Uuid::new_v4();
        let user_group_id = Uuid::new_v4();

        new_account(target_id, user_group_id).insert(&db).await.unwrap();
        let result = new_account(target_id, user_group_id).insert(&db).await;
        assert!(
            result.is_err(),
            "expected the unique (target_id, user_group_id) constraint to reject the duplicate"
        );
    }
}

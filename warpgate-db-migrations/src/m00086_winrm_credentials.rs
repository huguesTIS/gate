use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// `winrm_credentials` — a reusable admin WinRM credential (host/port/username +
/// `StoredSecret`-pattern password, NTLM domain) the new `winrm_powershell`
/// action connector runs PowerShell scripts with. Mirrors `ssh_credentials`'
/// role for the `ssh_command` connector. See `ARCHITECTURE_TECHNIQUE.md` §07.

pub mod winrm_credential {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "winrm_credentials")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        pub host: String,
        pub port: i32,
        pub use_tls: bool,
        pub username: String,
        pub password: String,
        pub domain: String,
        #[sea_orm(column_type = "Text")]
        pub description: String,
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
            .create_table(schema.create_table_from_entity(winrm_credential::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_winrm_credentials_name")
                    .table(winrm_credential::Entity)
                    .col(winrm_credential::Column::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(winrm_credential::Entity).to_owned())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use uuid::Uuid;
    use warpgate_db_entities::WinrmCredential;

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

    fn new_credential(name: &str) -> WinrmCredential::ActiveModel {
        WinrmCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(name.into()),
            host: Set("192.168.1.20".into()),
            port: Set(5985),
            use_tls: Set(false),
            username: Set("administrator".into()),
            password: Set("plaintext-for-now".into()),
            domain: Set(String::new()),
            description: Set(String::new()),
        }
    }

    #[tokio::test]
    async fn a_winrm_credential_can_be_inserted() {
        let db = migrated_db().await;
        new_credential("dc01").insert(&db).await.unwrap();
    }

    #[tokio::test]
    async fn credential_names_must_be_unique() {
        let db = migrated_db().await;
        new_credential("dc01").insert(&db).await.unwrap();
        let result = new_credential("dc01").insert(&db).await;
        assert!(result.is_err(), "expected the unique name constraint to reject the duplicate");
    }
}

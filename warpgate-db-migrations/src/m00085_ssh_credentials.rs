use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// `ssh_credentials` — a reusable admin SSH credential (host/port/username +
/// `StoredSecret`-pattern password) the new `ssh_command` action connector runs
/// commands with. Mirrors `ldap_servers`' role for the `ldap_group` connector.
/// See `ARCHITECTURE_TECHNIQUE.md` §07.

pub mod ssh_credential {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "ssh_credentials")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        pub host: String,
        pub port: i32,
        pub username: String,
        pub password: String,
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
            .create_table(schema.create_table_from_entity(ssh_credential::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_ssh_credentials_name")
                    .table(ssh_credential::Entity)
                    .col(ssh_credential::Column::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ssh_credential::Entity).to_owned())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use uuid::Uuid;
    use warpgate_db_entities::SshCredential;

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

    fn new_credential(name: &str) -> SshCredential::ActiveModel {
        SshCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(name.into()),
            host: Set("192.168.1.10".into()),
            port: Set(22),
            username: Set("admin".into()),
            password: Set("plaintext-for-now".into()),
            description: Set(String::new()),
        }
    }

    #[tokio::test]
    async fn a_ssh_credential_can_be_inserted() {
        let db = migrated_db().await;
        new_credential("prod-jump").insert(&db).await.unwrap();
    }

    #[tokio::test]
    async fn credential_names_must_be_unique() {
        let db = migrated_db().await;
        new_credential("prod-jump").insert(&db).await.unwrap();
        let result = new_credential("prod-jump").insert(&db).await;
        assert!(result.is_err(), "expected the unique name constraint to reject the duplicate");
    }
}

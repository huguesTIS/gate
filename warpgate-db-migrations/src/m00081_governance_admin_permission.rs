use sea_orm::sea_query::{Alias, ColumnDef};
use sea_orm_migration::prelude::*;

/// One coarse permission bit — `governance_manage` — covering create/edit/delete on
/// `user_groups`/`target_labels`/`access_policies`/`action_definitions`. Deliberately
/// not four-to-twelve fine-grained bits like `targets_*`/`users_*`: those model
/// mature, separately-staffed admin duties: this is one new subsystem, and the
/// finer split can happen later if a real need for it shows up.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("admin_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("governance_manage"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        let conn = manager.get_connection();
        let bool_true = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "TRUE",
            _ => "1",
        };
        conn.execute_unprepared(&format!(
            "UPDATE admin_roles SET governance_manage = {bool_true} WHERE name = 'warpgate:admin'",
        ))
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("admin_roles"))
                    .drop_column(Alias::new("governance_manage"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

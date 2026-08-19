use sea_orm_migration::prelude::*;

/// Adds `login_template` to `access_policies` — the effective target login name
/// for Requester/Managed connections governed by a policy (serialized
/// `warpgate_common::helpers::login_template::LoginNameTemplate`), modeled on
/// Netwrix Privilege Secure's "Login Account Template". `NULL` = portal username
/// as-is. See `ARCHITECTURE_TECHNIQUE.md` §10 ("Mode Requester").
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("access_policies"))
                    .add_column(ColumnDef::new(Alias::new("login_template")).json().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("access_policies"))
                    .drop_column(Alias::new("login_template"))
                    .to_owned(),
            )
            .await
    }
}

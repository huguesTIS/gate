use sea_orm_migration::prelude::*;

/// Adds `granted_at`/`expires_at`/`revoked_at` to `user_group_members`, mirroring
/// `user_roles` (`m00036_user_role_expiry_history`) — the mechanism behind
/// third-party account lifecycle: offboarding a tiers is letting their group
/// memberships expire (or revoking them early), not deleting rows. Without this,
/// membership was permanent from the moment it was granted.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_group_members"))
                    .add_column(ColumnDef::new(Alias::new("granted_at")).timestamp().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_group_members"))
                    .add_column(ColumnDef::new(Alias::new("expires_at")).timestamp().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_group_members"))
                    .add_column(ColumnDef::new(Alias::new("revoked_at")).timestamp().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_group_members"))
                    .drop_column(Alias::new("granted_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_group_members"))
                    .drop_column(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_group_members"))
                    .drop_column(Alias::new("revoked_at"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

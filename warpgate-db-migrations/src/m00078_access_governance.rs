use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// `user_groups` / `user_group_members` / `target_labels` / `access_policies` —
/// the group/label/policy model for `warpgate-access`. Foreign keys to
/// `targets`/`target_groups`/`users` are plain UUID columns, not DB-enforced
/// constraints, matching the existing `target_roles`/`user_roles` tables.

pub mod user_group {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_groups")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        #[sea_orm(column_type = "Text")]
        pub description: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod user_group_member {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_group_members")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i32,
        pub user_group_id: Uuid,
        pub user_id: Uuid,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod target_label {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "target_labels")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i32,
        pub target_id: Uuid,
        pub key: String,
        pub value: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod access_policy {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "access_policies")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        pub user_group_id: Uuid,
        pub target_group_id: Option<Uuid>,
        pub target_label_selector: Option<serde_json::Value>,
        pub valid_from: Option<OffsetDateTime>,
        pub valid_until: Option<OffsetDateTime>,
        pub priority: i32,
        pub active: bool,
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
            .create_table(schema.create_table_from_entity(user_group::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(user_group_member::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(target_label::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(access_policy::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_user_group_members_user_group_id")
                    .table(user_group_member::Entity)
                    .col(user_group_member::Column::UserGroupId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_group_members_user_id")
                    .table(user_group_member::Entity)
                    .col(user_group_member::Column::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_target_labels_target_id")
                    .table(target_label::Entity)
                    .col(target_label::Column::TargetId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_policies_user_group_id")
                    .table(access_policy::Entity)
                    .col(access_policy::Column::UserGroupId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(access_policy::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(target_label::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(user_group_member::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(user_group::Entity).to_owned())
            .await?;
        Ok(())
    }
}

use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// `action_definitions` / `action_executions` / `access_policy_actions` — the
/// Grant/Remove action engine for `warpgate-actions`. See
/// `ARCHITECTURE_TECHNIQUE.md` §07.

pub mod action_definition {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
    pub enum ActionKind {
        #[sea_orm(string_value = "grant")]
        Grant,
        #[sea_orm(string_value = "remove")]
        Remove,
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
    pub enum ConnectorType {
        #[sea_orm(string_value = "ldap_group")]
        LdapGroup,
    }

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "action_definitions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        pub kind: ActionKind,
        pub paired_action_id: Option<Uuid>,
        pub connector_type: ConnectorType,
        pub config: serde_json::Value,
        pub continue_on_error: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod action_execution {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
    pub enum ExecutionPhase {
        #[sea_orm(string_value = "pre_session")]
        PreSession,
        #[sea_orm(string_value = "post_session")]
        PostSession,
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
    pub enum ExecutionStatus {
        #[sea_orm(string_value = "pending")]
        Pending,
        #[sea_orm(string_value = "running")]
        Running,
        #[sea_orm(string_value = "succeeded")]
        Succeeded,
        #[sea_orm(string_value = "failed")]
        Failed,
    }

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "action_executions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub session_id: Uuid,
        pub action_definition_id: Uuid,
        pub phase: ExecutionPhase,
        pub status: ExecutionStatus,
        pub context: serde_json::Value,
        pub attempts: i32,
        #[sea_orm(column_type = "Text", nullable)]
        pub last_error: Option<String>,
        pub created_at: OffsetDateTime,
        pub executed_at: Option<OffsetDateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod access_policy_action {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "access_policy_actions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i32,
        pub access_policy_id: Uuid,
        pub action_definition_id: Uuid,
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
            .create_table(schema.create_table_from_entity(action_definition::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(action_execution::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(access_policy_action::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_action_definitions_paired_action_id")
                    .table(action_definition::Entity)
                    .col(action_definition::Column::PairedActionId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_action_executions_session_id")
                    .table(action_execution::Entity)
                    .col(action_execution::Column::SessionId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_action_executions_status")
                    .table(action_execution::Entity)
                    .col(action_execution::Column::Status)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_policy_actions_policy_id")
                    .table(access_policy_action::Entity)
                    .col(access_policy_action::Column::AccessPolicyId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(access_policy_action::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(action_execution::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(action_definition::Entity).to_owned())
            .await?;
        Ok(())
    }
}

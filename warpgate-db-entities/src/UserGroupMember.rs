use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "user_group_members")]
#[oai(rename = "UserGroupMember")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub user_group_id: Uuid,
    pub user_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    UserGroup,
    User,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::UserGroup => Entity::belongs_to(super::UserGroup::Entity)
                .from(Column::UserGroupId)
                .to(super::UserGroup::Column::Id)
                .into(),
            Self::User => Entity::belongs_to(super::User::Entity)
                .from(Column::UserId)
                .to(super::User::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}

use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "target_labels")]
#[oai(rename = "TargetLabel")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub target_id: Uuid,
    pub key: String,
    pub value: String,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Target,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Target => Entity::belongs_to(super::Target::Entity)
                .from(Column::TargetId)
                .to(super::Target::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}

use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "access_policies")]
#[oai(rename = "AccessPolicy")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub user_group_id: Uuid,
    /// Static target-group match. `None` = this policy doesn't select by group.
    pub target_group_id: Option<Uuid>,
    /// Label-selector match, as a JSON array of `{"key": ..., "value": ...}`
    /// objects — every entry must match a label on the target. `None` = this
    /// policy doesn't select by label.
    pub target_label_selector: Option<serde_json::Value>,
    /// Policy is not in effect before this time. `None` = no lower bound.
    pub valid_from: Option<OffsetDateTime>,
    /// Policy is not in effect after this time. `None` = no upper bound.
    pub valid_until: Option<OffsetDateTime>,
    /// Higher wins when multiple policies disagree on the same user/target pair.
    pub priority: i32,
    pub active: bool,
    /// Effective target login name for Requester/Managed connections governed by
    /// this policy, serialized `warpgate_common::helpers::login_template::LoginNameTemplate`.
    /// `None` = use the portal username as-is.
    pub login_template: Option<serde_json::Value>,
}

impl Model {
    /// Whether this policy is enabled and currently inside its validity window.
    /// Doesn't check group/label membership — see `warpgate-access` for that.
    pub fn in_effect(&self) -> bool {
        if !self.active {
            return false;
        }
        let now = OffsetDateTime::now_utc();
        if self.valid_from.is_some_and(|from| now < from) {
            return false;
        }
        if self.valid_until.is_some_and(|until| now > until) {
            return false;
        }
        true
    }
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    UserGroup,
    TargetGroup,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::UserGroup => Entity::belongs_to(super::UserGroup::Entity)
                .from(Column::UserGroupId)
                .to(super::UserGroup::Column::Id)
                .into(),
            Self::TargetGroup => Entity::belongs_to(super::TargetGroup::Entity)
                .from(Column::TargetGroupId)
                .to(super::TargetGroup::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}

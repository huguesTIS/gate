use poem_openapi::Object;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "user_group_members")]
#[oai(rename = "UserGroupMember")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub user_group_id: Uuid,
    pub user_id: Uuid,
    /// When this membership was granted.
    pub granted_at: Option<OffsetDateTime>,
    /// When this membership expires (null = never) — the mechanism behind
    /// third-party account lifecycle: offboarding a tiers is letting their group
    /// memberships expire, not deleting rows.
    pub expires_at: Option<OffsetDateTime>,
    /// When this membership was revoked early (null = not revoked).
    pub revoked_at: Option<OffsetDateTime>,
}

impl Model {
    pub fn expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
    }
    pub fn active(&self) -> bool {
        self.revoked_at.is_none() && !self.expired()
    }
}

impl Entity {
    pub fn find_active() -> Select<Self> {
        Self::find().filter(
            Column::ExpiresAt
                .is_null()
                .or(Column::ExpiresAt.gt(OffsetDateTime::now_utc()))
                .and(Column::RevokedAt.is_null()),
        )
    }

    pub async fn idempotent_grant(
        db: &DatabaseConnection,
        user_group_id: Uuid,
        user_id: Uuid,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<Model, DbErr> {
        let existing = Self::find()
            .filter(Column::UserGroupId.eq(user_group_id))
            .filter(Column::UserId.eq(user_id))
            .one(db)
            .await?;

        let now = OffsetDateTime::now_utc();

        Ok(if let Some(existing) = existing {
            if existing.active() {
                return Ok(existing);
            }
            let mut model: ActiveModel = existing.into();
            model.granted_at = Set(Some(now));
            model.expires_at = Set(expires_at);
            model.revoked_at = Set(None);
            model.update(db).await?
        } else {
            let values = ActiveModel {
                user_group_id: Set(user_group_id),
                user_id: Set(user_id),
                granted_at: Set(Some(now)),
                expires_at: Set(expires_at),
                revoked_at: Set(None),
                ..Default::default()
            };
            values.insert(db).await?
        })
    }
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

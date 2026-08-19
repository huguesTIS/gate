use sea_orm::Set;
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::ForeignKeyAction;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{UserAuthCredential, UserTotpCredential};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "credentials_otp")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret_key: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    User,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::User => Entity::belongs_to(super::User::Entity)
                .from(Column::UserId)
                .to(super::User::Column::Id)
                .on_delete(ForeignKeyAction::Cascade)
                .into(),
        }
    }
}

impl Related<super::User::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// Not used to load a credential for actual verification — `secret_key` may be a
/// vault reference or an envelope, not the raw seed; use
/// `warpgate_common::helpers::otp::resolve_otp_key` for that (see
/// `User::load_details`). Kept as a plain structural conversion since some callers
/// only need the row shape, not a usable key.
impl From<Model> for UserTotpCredential {
    fn from(credential: Model) -> Self {
        Self {
            key: credential.secret_key.into(),
        }
    }
}

impl From<Model> for UserAuthCredential {
    fn from(model: Model) -> Self {
        Self::Totp(model.into())
    }
}

/// Not used to persist a credential — stores the raw seed with no externalization
/// (vault-or-envelope). Use `warpgate_common::helpers::otp::externalize_otp_key`
/// and set `secret_key` explicitly instead (see the `/profile/credentials/otp` and
/// admin OTP-credential endpoints).
impl From<UserTotpCredential> for ActiveModel {
    fn from(credential: UserTotpCredential) -> Self {
        Self {
            secret_key: Set(credential.key.expose_secret().clone()),
            ..Default::default()
        }
    }
}

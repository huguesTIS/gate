use sea_orm::entity::prelude::*;

/// Single-row control table (`id = 1`) toggled around any legitimate bulk
/// modification of `target = 'audit'` rows in `log` — currently just the
/// retention purge in `warpgate-core::db::cleanup_db`. The `log` table has
/// `BEFORE UPDATE`/`BEFORE DELETE` triggers (see the migration that creates
/// this table) that reject touching an audit row unless `enabled` is set,
/// so tampering with the audit trail requires going through this gate —
/// not a silver bullet against a fully compromised app process using the
/// same DB credentials, but it stops direct/accidental tampering that
/// doesn't know to flip this flag first.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_maintenance_mode")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub enabled: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

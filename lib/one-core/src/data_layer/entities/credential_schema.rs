use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credential_schema")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,

    pub organisation_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::claim_schema::Entity")]
    ClaimSchema,
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum RevocationMethod {
    #[default]
    #[sea_orm(string_value = "STATUSLIST2021")]
    StatusList2021,
    #[sea_orm(string_value = "LVVC")]
    Lvvc,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum Format {
    #[default]
    #[sea_orm(string_value = "JWT")]
    Jwt,
    #[sea_orm(string_value = "SD_JWT")]
    SdJwt,
    #[sea_orm(string_value = "JSON_LD")]
    JsonLd,
    #[sea_orm(string_value = "MDOC")]
    Mdoc,
}

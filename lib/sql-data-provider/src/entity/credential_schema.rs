use dto_mapper::{From, Into};
use one_core::model::credential_schema::WalletStorageTypeEnum as ModelWalletStorageTypeEnum;
use sea_orm::entity::prelude::*;
use serde::Deserialize;
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
    pub format: String,
    pub revocation_method: String,
    pub wallet_storage_type: Option<WalletStorageType>,

    pub organisation_id: String,
}

#[derive(
    Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize,
)]
#[from(ModelWalletStorageTypeEnum)]
#[into(ModelWalletStorageTypeEnum)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "wallet_storage_type"
)]
#[serde(rename_all = "UPPERCASE")]
pub enum WalletStorageType {
    #[sea_orm(string_value = "HARDWARE")]
    Hardware,
    #[sea_orm(string_value = "SOFTWARE")]
    Software,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential::Entity")]
    Credential,
    #[sea_orm(has_many = "super::credential_schema_claim_schema::Entity")]
    CredentialSchemaClaimSchema,
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::credential_schema_claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchemaClaimSchema.def()
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        super::credential_schema_claim_schema::Relation::ClaimSchema.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::credential_schema_claim_schema::Relation::CredentialSchema
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}

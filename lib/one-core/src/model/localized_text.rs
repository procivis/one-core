use shared_types::EntityId;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct LocalizedText {
    pub entity_id: EntityId,
    pub field: LocalizedTextField,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub lang: String,
    pub value: String,
    pub entity_type: LocalizedTextEntityType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalizedTextEntityType {
    CredentialSchema,
    ClaimSchema,
    Identifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalizedTextField {
    Name,
    Description,
    LogoAltText,
}

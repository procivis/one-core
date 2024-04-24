use shared_types::JsonLdContextId;
use time::OffsetDateTime;
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonLdContext {
    pub id: JsonLdContextId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub context: Vec<u8>,

    pub url: Url,
    pub hit_counter: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct JsonLdContextRelations {}

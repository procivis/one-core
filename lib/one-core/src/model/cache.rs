use crate::model::remote_entity_cache::CacheType;

#[derive(Debug, Clone)]
pub struct CachePreferences {
    pub bypass: Vec<CacheType>,
}

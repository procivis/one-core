use std::collections::HashMap;

use super::dto::JsonLDContextDTO;

impl Default for JsonLDContextDTO {
    fn default() -> Self {
        Self {
            version: "1.1".to_string(),
            protected: true,
            id: "@id".to_string(),
            r#type: "@type".to_string(),
            entities: HashMap::default(),
        }
    }
}

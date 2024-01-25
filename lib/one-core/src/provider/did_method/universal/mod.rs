use async_trait::async_trait;
use shared_types::{DidId, DidValue};

use crate::model::key::Key;

use super::{dto::DidDocumentDTO, DidCapabilities, DidMethodError, Operation};

pub struct UniversalDidMethod {}

#[async_trait]
impl super::DidMethod for UniversalDidMethod {
    fn get_method(&self) -> String {
        todo!()
    }

    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        _key: &Option<Key>,
    ) -> Result<DidValue, DidMethodError> {
        todo!()
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, _did_value: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        todo!()
    }

    fn update(&self) -> Result<(), DidMethodError> {
        todo!()
    }

    fn can_be_deactivated(&self) -> bool {
        todo!()
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE],
            key_algorithms: vec![],
        }
    }
}

#[cfg(test)]
mod test;

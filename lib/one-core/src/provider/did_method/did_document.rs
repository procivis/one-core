use super::model::{DidDocument, DidVerificationMethod};
use crate::model::did::KeyRole;

impl DidDocument {
    pub fn find_verification_method(
        &self,
        id: Option<&str>,
        key_role: Option<KeyRole>,
    ) -> Option<&DidVerificationMethod> {
        let keys_for_role = key_role.map(|role| self.verification_method_ids_for_role(role));

        let mut verification_methods = self.verification_method.iter().filter(|vm| {
            keys_for_role
                .as_ref()
                .map(|keys| keys.contains(&vm.id))
                .unwrap_or(true)
        });

        if let Some(id) = id {
            verification_methods.find(|vm| vm.id == id)
        } else {
            verification_methods.next()
        }
    }

    pub fn verification_method_ids_for_role(&self, role: KeyRole) -> Vec<String> {
        match role {
            KeyRole::Authentication => self.authentication.clone().unwrap_or_default(),
            KeyRole::AssertionMethod => self.assertion_method.clone().unwrap_or_default(),
            KeyRole::KeyAgreement => self.key_agreement.clone().unwrap_or_default(),
            KeyRole::CapabilityInvocation => self.capability_invocation.clone().unwrap_or_default(),
            KeyRole::CapabilityDelegation => self.capability_delegation.clone().unwrap_or_default(),
        }
    }
}

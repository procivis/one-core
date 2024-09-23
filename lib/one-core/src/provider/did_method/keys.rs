//! Implementation of keys validation of DIDs.

use crate::provider::did_method::model::AmountOfKeys;

#[derive(Debug, Clone)]
pub struct MinMax<const N: usize> {
    pub min: usize,
    pub max: usize,
}

impl<const N: usize> MinMax<N> {
    fn contains(&self, number: usize) -> bool {
        (&self.min..=&self.max).contains(&&number)
    }
}

impl<const N: usize> Default for MinMax<N> {
    fn default() -> Self {
        Self { min: 1, max: 1 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Keys {
    pub global: MinMax<1>,
    pub authentication: MinMax<0>,
    pub assertion_method: MinMax<0>,
    pub key_agreement: MinMax<0>,
    pub capability_invocation: MinMax<0>,
    pub capability_delegation: MinMax<0>,
}

impl Keys {
    pub fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        self.global.contains(keys.global)
            && self.authentication.contains(keys.authentication)
            && self.assertion_method.contains(keys.assertion_method)
            && self.key_agreement.contains(keys.key_agreement)
            && self
                .capability_invocation
                .contains(keys.capability_invocation)
            && self
                .capability_delegation
                .contains(keys.capability_delegation)
    }
}

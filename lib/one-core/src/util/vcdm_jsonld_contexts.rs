use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::model::Context;

pub fn vcdm_v1_base_context(additional_contexts: Option<Vec<ContextType>>) -> Vec<ContextType> {
    let mut result = vec![
        ContextType::Url(Context::CredentialsV1.to_url()),
        ContextType::Url(Context::BitstringStatusList.to_url()),
        ContextType::Url(Context::DataIntegrityV2.to_url()),
    ];

    if let Some(additional_contexts) = additional_contexts {
        result.extend(additional_contexts);
    }

    result
}

pub fn vcdm_v2_base_context(additional_contexts: Option<Vec<ContextType>>) -> Vec<ContextType> {
    let mut result = vec![ContextType::Url(Context::CredentialsV2.to_url())];

    if let Some(additional_contexts) = additional_contexts {
        result.extend(additional_contexts);
    }
    result
}

pub fn vcdm_type(additional_types: Option<Vec<String>>) -> Vec<String> {
    let mut types = vec!["VerifiableCredential".to_string()];
    if let Some(additional_types) = additional_types {
        types.extend(additional_types);
    };
    types
}

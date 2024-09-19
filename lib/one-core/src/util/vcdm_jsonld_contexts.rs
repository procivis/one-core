use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::model::Context;

pub fn vcdm_v1_base_context() -> Vec<ContextType> {
    vec![
        ContextType::Url(Context::CredentialsV1.to_url()),
        ContextType::Url(Context::BitstringStatusList.to_url()),
        ContextType::Url(Context::DataIntegrityV2.to_url()),
    ]
}

pub fn vcdm_v2_base_context() -> Vec<ContextType> {
    vec![ContextType::Url(Context::CredentialsV2.to_url())]
}

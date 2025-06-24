use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::OpenID4VP25HTTP;
use super::model::OpenID4Vp25Params;
use crate::common_mapper::PublicKeyWithJwk;
use crate::config::core_config::{CoreConfig, FormatType};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaType, LayoutType};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::verification_protocol::dto::ShareResponse;
use crate::provider::verification_protocol::openid4vp::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, ClientIdScheme,
    OpenID4VCPresentationHolderParams, OpenID4VCPresentationVerifierParams,
    OpenID4VCRedirectUriParams, OpenID4VPClientMetadata, OpenID4VPPresentationDefinition,
};
use crate::provider::verification_protocol::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocol,
};
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::proof::dto::ShareProofRequestParamsDTO;

#[derive(Default)]
struct TestInputs {
    pub formatter_provider: MockCredentialFormatterProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub certificate_validator: MockCertificateValidator,
    pub params: Option<OpenID4Vp25Params>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VP25HTTP {
    OpenID4VP25HTTP::new(
        Some("http://base_url".to_string()),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.certificate_validator),
        Arc::new(ReqwestClient::default()),
        inputs.params.unwrap_or(generic_params()),
        Arc::new(CoreConfig::default()),
    )
}

fn generic_params() -> OpenID4Vp25Params {
    OpenID4Vp25Params {
        allow_insecure_http_transport: true,
        use_request_uri: false,
        url_scheme: "openid4vp".to_string(),
        holder: OpenID4VCPresentationHolderParams {
            supported_client_id_schemes: vec![
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation,
            ],
        },
        verifier: OpenID4VCPresentationVerifierParams {
            supported_client_id_schemes: vec![
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation,
            ],
        },
        redirect_uri: OpenID4VCRedirectUriParams {
            enabled: true,
            allowed_schemes: vec!["https".to_string()],
        },
    }
}

#[tokio::test]
async fn test_share_proof() {
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    let arc = Arc::new(credential_formatter);
    formatter_provider
        .expect_get_formatter()
        .returning(move |_| Some(arc.clone()));
    let protocol = setup_protocol(TestInputs {
        formatter_provider,
        ..Default::default()
    });

    let proof_id = Uuid::new_v4();
    let proof = test_proof(proof_id, "JWT");

    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let encryption_key_jwk = PublicKeyWithJwk {
        key_id: Uuid::new_v4().into(),
        jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: None,
        }),
    };
    let vp_formats = HashMap::new();

    let ShareResponse {
        url,
        interaction_id,
        ..
    } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            Some(encryption_key_jwk),
            vp_formats,
            type_to_descriptor_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();

    let url: Url = url.parse().unwrap();
    let query_pairs: HashMap<Cow<'_, str>, Cow<'_, str>> = url.query_pairs().collect();

    assert_eq!(
        HashSet::<&str>::from_iter([
            "response_mode",
            "nonce",
            "response_type",
            "client_metadata",
            "state",
            "response_uri",
            "presentation_definition",
            "client_id"
        ]),
        HashSet::from_iter(query_pairs.keys().map(|k| k.as_ref()))
    );

    assert_eq!("vp_token", query_pairs.get("response_type").unwrap());

    assert_eq!("direct_post", query_pairs.get("response_mode").unwrap());

    assert_eq!(
        &interaction_id.to_string(),
        query_pairs.get("state").unwrap()
    );

    assert_eq!(
        "http://base_url/ssi/openid4vp/draft-25/response",
        query_pairs.get("response_uri").unwrap()
    );

    assert_eq!(
        "redirect_uri:http://base_url/ssi/openid4vp/draft-25/response",
        query_pairs.get("client_id").unwrap()
    );

    let returned_presentation_definition = serde_json::from_str::<OpenID4VPPresentationDefinition>(
        query_pairs.get("presentation_definition").unwrap(),
    )
    .unwrap();

    let returned_client_metadata = serde_json::from_str::<OpenID4VPClientMetadata>(
        query_pairs.get("client_metadata").unwrap(),
    )
    .unwrap();

    assert_eq!(returned_client_metadata.jwks.unwrap().keys.len(), 1);
    assert_eq!(
        returned_client_metadata.authorization_encrypted_response_alg,
        Some(AuthorizationEncryptedResponseAlgorithm::EcdhEs)
    );
    assert_eq!(
        returned_client_metadata.authorization_encrypted_response_enc,
        Some(AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM)
    );
    assert_eq!(returned_presentation_definition.input_descriptors.len(), 1);
    assert_eq!(
        returned_presentation_definition.input_descriptors[0].id,
        "input_0"
    );
    assert_eq!(
        returned_presentation_definition.input_descriptors[0]
            .constraints
            .fields
            .len(),
        1
    );
    assert_eq!(
        returned_presentation_definition.input_descriptors[0]
            .constraints
            .fields[0]
            .path,
        vec!["$.credentialSchema.id"]
    );
}

fn test_proof(proof_id: Uuid, credential_format: &str) -> Proof {
    Proof {
        id: proof_id.into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT25".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "test-share-proof".into(),
            expire_duration: 123,
            imported_source_url: None,
            organisation: None,
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: None,
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    external_schema: false,
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "test-credential-schema".to_string(),
                    format: credential_format.to_string(),
                    revocation_method: "NONE".to_string(),
                    wallet_storage_type: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_id: "test_schema_id".to_string(),
                    schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                    imported_source_url: "test_imported_src_url".to_string(),
                    allow_suspension: false,
                    claim_schemas: None,
                    organisation: None,
                }),
            }]),
        }),
        claims: None,
        verifier_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: None,
            key: None,
            certificates: None,
        }),
        holder_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
    }
}

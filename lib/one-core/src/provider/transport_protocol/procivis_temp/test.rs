use std::sync::Arc;
use time::OffsetDateTime;

use crate::{
    model::{credential::Credential, proof::Proof},
    provider::{
        credential_formatter::provider::MockCredentialFormatterProvider,
        key_storage::provider::MockKeyProvider,
        transport_protocol::{TransportProtocol, TransportProtocolError},
    },
    repository::{
        credential_schema_repository::MockCredentialSchemaRepository,
        did_repository::MockDidRepository,
        interaction_repository::MockInteractionRepository,
        mock::{
            credential_repository::MockCredentialRepository, proof_repository::MockProofRepository,
        },
    },
};

use super::ProcivisTemp;

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub did_repository: MockDidRepository,
    pub proof_repository: MockProofRepository,
    pub interaction_repository: MockInteractionRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub key_provider: MockKeyProvider,
}

fn setup_protocol(base_url: Option<String>, repositories: Repositories) -> ProcivisTemp {
    ProcivisTemp::new(
        base_url,
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.proof_repository),
        Arc::new(repositories.interaction_repository),
        Arc::new(repositories.credential_schema_repository),
        Arc::new(repositories.did_repository),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.key_provider),
    )
}

fn generate_credential(redirect_uri: Option<String>) -> Credential {
    Credential {
        id: Default::default(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: vec![],
        transport: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri,
        state: None,
        claims: None,
        issuer_did: None,
        holder_did: None,
        schema: None,
        interaction: None,
        revocation_list: None,
        key: None,
    }
}

fn generate_proof(redirect_uri: Option<String>) -> Proof {
    Proof {
        id: Default::default(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri,
        state: None,
        schema: None,
        claims: None,
        verifier_did: None,
        holder_did: None,
        interaction: None,
    }
}

#[tokio::test]
async fn test_share_credential_no_base_url() {
    let protocol = setup_protocol(None, Repositories::default());
    let credential = generate_credential(None);

    let result = protocol.share_credential(&credential).await;
    assert!(matches!(
        result,
        Err(TransportProtocolError::MissingBaseUrl)
    ));
}

#[tokio::test]
async fn test_share_credential_success_no_redirect_uri() {
    let protocol = setup_protocol(Some("http://base_url".to_string()), Repositories::default());
    let credential = generate_credential(None);

    let result = protocol.share_credential(&credential).await.unwrap();
    assert_eq!("http://base_url/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential=00000000-0000-0000-0000-000000000000", result);
}

#[tokio::test]
async fn test_share_credential_success_with_redirect_uri_is_percent_encoded() {
    let protocol = setup_protocol(Some("http://base_url".to_string()), Repositories::default());
    let credential = generate_credential(Some("http://base_url/redirect?queryParam=1".to_string()));

    let result = protocol.share_credential(&credential).await.unwrap();
    assert_eq!("http://base_url/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential=00000000-0000-0000-0000-000000000000&redirect_uri=http%3A%2F%2Fbase_url%2Fredirect%3FqueryParam%3D1", result);
}

#[tokio::test]
async fn test_share_proof_no_base_url() {
    let protocol = setup_protocol(None, Repositories::default());
    let proof = generate_proof(None);

    let result = protocol.share_proof(&proof).await;
    assert!(matches!(
        result,
        Err(TransportProtocolError::MissingBaseUrl)
    ));
}

#[tokio::test]
async fn test_share_proof_success_no_redirect_uri() {
    let protocol = setup_protocol(Some("http://base_url".to_string()), Repositories::default());
    let proof = generate_proof(None);

    let result = protocol.share_proof(&proof).await.unwrap();
    assert_eq!("http://base_url/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof=00000000-0000-0000-0000-000000000000", result);
}

#[tokio::test]
async fn test_share_proof_success_with_redirect_uri_is_percent_encoded() {
    let protocol = setup_protocol(Some("http://base_url".to_string()), Repositories::default());
    let proof = generate_proof(Some("http://base_url/redirect?queryParam=1".to_string()));

    let result = protocol.share_proof(&proof).await.unwrap();
    assert_eq!("http://base_url/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof=00000000-0000-0000-0000-000000000000&redirect_uri=http%3A%2F%2Fbase_url%2Fredirect%3FqueryParam%3D1", result);
}

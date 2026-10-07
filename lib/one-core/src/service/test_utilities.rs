#![allow(clippy::unwrap_used)]

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indoc::indoc;
use serde::{Deserialize, Serialize};
use shared_types::{DidValue, IdentifierId, OrganisationId};
use similar_asserts::assert_eq;
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use standardized_types::openid4vp::dcql::{
    CredentialFormat, CredentialQuery, DcqlQuery, W3cVcMeta,
};
use time::OffsetDateTime;
use time::macros::datetime;
use url::Url;
use uuid::Uuid;

use crate::config::core_config::{
    AppConfig, IdentifierType as ConfigIdentifierType, InputFormat, IssuanceProtocolType,
    KeyAlgorithmType, KeyStorageType, RevocationType, VerificationProtocolType,
};
use crate::model::blob::{Blob, BlobType};
use crate::model::certificate::{Certificate, CertificateRole, CertificateState};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialCommon, CredentialRole, CredentialStateEnum, CredentialType,
};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity, WalletAttestation};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::{Did, DidType};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::ProofSchema;
use crate::model::trust_collection::TrustCollection;
use crate::model::trust_list_publication::TrustListPublication;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::provider::credential_formatter::model::{Features, FormatterCapabilities};
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomConfig {}

pub fn generic_config() -> AppConfig<CustomConfig> {
    let config = indoc! {"
        app:
            auth:
                mode: UNSAFE_STATIC
                staticToken: \"test\"
        transport:
            HTTP:
                type: 'HTTP'
                display: 'transport.http'
                enabled: true
                order: 0
                params: {}
        format:
            JWT:
                type: 'JWT'
                display: 'display'
                order: 0
                params:
                    public:
                        leewaySeconds: 60
                        embedLayoutProperties: true
            SD_JWT:
                type: 'SD_JWT'
                display: 'format.sdjwt'
                order: 1
                params:
                    public:
                        leewaySeconds: 60
                        embedLayoutProperties: true
            SD_JWT_VC:
                type: 'SD_JWT_VC'
                display: 'format.sdjwtvc'
                order: 1
                params:
                    public:
                        leewaySeconds: 60
                        embedLayoutProperties: true
            JSON_LD_CLASSIC:
                type: 'JSON_LD_CLASSIC'
                display: 'display'
                order: 2
                params:
                    public:
                        leewaySeconds: 60
            MDOC:
              type: 'MDOC'
              display: 'format.mdoc'
              order: 4
              params:
                public:
                  expirationSeconds: 259200 # 72h in seconds
                  msoExpectedUpdateInSeconds: 86400 # 24h in seconds
                  msoMinimumRefreshSeconds: 300 # 5min in seconds
                  leewaySeconds: 60
        identifier:
          DID:
            display: 'identifier.did'
            enabled: true
            order: 0
          CERTIFICATE:
            display: 'identifier.certificate'
            enabled: true
            order: 1
          KEY:
            display: 'identifier.key'
            enabled: true
            order: 2
          CA:
            display: 'identifier.ca'
            enabled: true
            order: 3
        issuanceProtocol:
            OPENID4VCI_FINAL1:
                display: 'display.openid4vciFinal1'
                order: 2
                type: 'OPENID4VCI_FINAL1'
                params:
                    public:
                        oauthAttestationLeewaySeconds: 60
                        keyAttestationLeewaySeconds: 60
                        preAuthorizedCodeExpiresInSeconds: 300
                        tokenExpiresInSeconds: 86400
                        refreshExpiresInSeconds: 886400
                        redirectUri:
                            enabled: true
                            allowedSchemes: [ https ]
                    private:
                        encryption: '93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e'
                        nonce:
                            signingKey: '93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e'
                            expirationSeconds: 300
                            leewaySeconds: 0
        verificationProtocol:
            OPENID4VP_FINAL1:
                display: 'display'
                order: 3
                type: 'OPENID4VP_FINAL1'
                params:
                    public:
                        verifier:
                            supportedClientIdSchemes: [ verifier_attestation, redirect_uri, did ]
                        holder:
                            supportedClientIdSchemes: [ redirect_uri, verifier_attestation, did ]
                        redirectUri:
                            enabled: true
                            allowedSchemes: [ https ]
            ISO_MDL:
                type: 'ISO_MDL'
                display: 'exchange.isoMdl'
                order: 4
        revocation:
            BITSTRINGSTATUSLIST:
                display: 'display'
                order: 1
                type: 'BITSTRINGSTATUSLIST'
                params: null
        did:
            KEY:
                display: 'did.key'
                order: 0
                type: 'KEY'
                params: null
        datatype:
            STRING:
                display: 'display'
                type: 'STRING'
                order: 100
                params: null
            NUMBER:
                display: 'display'
                type: 'NUMBER'
                order: 200
                params: null
            OBJECT:
                display: 'display'
                type: 'OBJECT'
                order: 300
                params: null
            EAA_CATEGORY:
                display: 'display'
                type: 'ENUM'
                order: 500
                params:
                    public:
                        values:
                            - value: urn:etsi:esi:eaa:eu:pub
                              display: 'datatype.category.public'
                            - value: urn:etsi:esi:eaa:eu:qualified
                              display: 'datatype.category.qualified'
            SWIYU_PICTURE:
                display: 'display'
                type: 'SWIYU_PICTURE'
                order: 403
                params:
                public:
                    accept:
                        - image/jpeg
                    fileSize: 4194304
                    showAs: IMAGE
        keyAlgorithm:
            EDDSA:
                display: 'display'
                order: 0
                type: 'EDDSA'
                params:
                    public:
                        algorithm: 'Ed25519'
            BBS_PLUS:
                display: 'keyAlgorithm.bbs_plus'
                order: 2
                type: 'BBS_PLUS'
                params: null
        keyStorage:
            INTERNAL:
                display: 'display'
                type: 'INTERNAL'
                order: 0
                params: null
            SECURE_ELEMENT:
                display: 'keyStorage.secureElement'
                type: 'SECURE_ELEMENT'
                order: 3
                params:
                  private:
                    aliasPrefix: 'ch.procivis.one.wallet.keys'
        keySecurityLevel:
            BASIC:
                display: keySecurityLevel.basic
                order: 10
                params:
                    public:
                        holder:
                            priority: 10
                            keyStorages: ['INTERNAL']
        holderKeyStorage:
            SOFTWARE:
                display: 'display'
                order: 10
            HARDWARE:
                display: 'display'
                order: 14
            REMOTE_SECURE_ELEMENT:
                display: 'display'
                order: 20
        task: {}
        cacheEntities: {}
        blobStorage: {}
        walletProvider: {}
        credentialIssuer: {}
        verificationEngagement:
            QR_CODE:
                display: verificationEngagement.qrCode
                order: 1
                enabled: true
        signer: {}
        verifierProvider: {}
        documentSignerProvider: {}
        transactionDataProvider: {}
        trustListPublisher: {}
        trustListSubscriber: {}
        ecosystem: {}
        globalSettings:
            certificateValidation:
                leewaySeconds: 60
            httpClient:
                insecureHttpTransportAllowed: true
                maxRedirects: 3
    "};

    AppConfig::parse(vec![InputFormat::yaml_str(config)]).unwrap()
}

pub fn dummy_credential() -> Credential {
    dummy_credential_with_exchange("EXCHANGE")
}

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

pub fn dummy_credential_with_exchange(exchange: &str) -> Credential {
    let claim_schema_id = Uuid::new_v4().into();
    let credential_id = Uuid::new_v4().into();

    let credential_schema_id = Uuid::new_v4().into();
    let format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "format".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: Default::default(),
    };
    CredentialBuilder {
        common: CredentialCommon {
            expires_at: None,
            ecosystem: None,
            id: credential_id,
            created_date: crate::clock::now_utc(),
            issuance_date: None,
            last_modified: crate::clock::now_utc(),
            deleted_at: None,
            protocol: exchange.to_owned(),
            redirect_uri: None,
            state: CredentialStateEnum::Pending,
            profile: None,
            schema: CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: true,
                id: credential_schema_id,
                deleted_at: None,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "schema".to_string(),
                wallet_attestation: WalletAttestation {
                    require_instance_attestation: false,
                    key_storage_security_level: Some(KeyStorageSecurity::Basic),
                    preferred_key_storage_attestation_lifetime: None,
                    preferred_instance_attestation_lifetime: None,
                },
                formats: vec![format.clone()].into(),
                imported_source_url: "CORE_URL".to_string(),
                claim_schemas: vec![ClaimSchema {
                    id: claim_schema_id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]
                .into(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            }
            .into(),
            interaction: Some(
                Interaction {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    data: Some(b"interaction data".to_vec()),
                    organisation: dummy_organisation(None).into(),
                    interaction_type: InteractionType::Issuance,
                    expires_at: None,
                    ecosystem: None,
                    ecosystem_data: Default::default(),
                }
                .into(),
            ),
        },
        consumed_at: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        suspend_end_date: None,
        claims: vec![Claim {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            value: Some("claim value".to_string()),
            path: "key".to_string(),
            selectively_disclosable: false,
            schema: ClaimSchema {
                id: claim_schema_id,
                key: "key".to_string(),
                data_type: "STRING".to_string(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                array: false,
                metadata: false,
                required: true,
                translations: Default::default(),
            }
            .into(),
        }]
        .into(),
        issuer_identifier: Some(
            Identifier {
                data: IdentifierData::Did((dummy_did()).into()),
                ..dummy_identifier()
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        credential_blob_id: None,
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    }
    .build()
}

pub fn dummy_blob() -> Blob {
    Blob {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: vec![1, 2, 3, 4, 5],
        r#type: BlobType::Credential,
    }
}

pub fn dummy_did() -> Did {
    Did {
        deleted_at: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "John".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "INTERNAL".into(),
        keys: Default::default(),
        organisation: dummy_organisation(None).into(),
        deactivated: false,
        log: None,
    }
}

pub fn dummy_identifier() -> Identifier {
    Identifier {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "identifier".to_string(),
        data: IdentifierData::Did(dummy_did().into()),
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(None).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    }
}

pub fn dummy_certificate(identifier_id: IdentifierId) -> Certificate {
    Certificate {
        id: Uuid::new_v4().into(),
        identifier_id,
        organisation: dummy_organisation(None).into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        deleted_at: None,
        expiry_date: datetime!(2042-04-02 21:37 +1),
        name: "certificate".to_string(),
        chain: "dummy chaing".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        roles: vec![
            CertificateRole::Authentication,
            CertificateRole::AssertionMethod,
        ],
        key: None,
    }
}

pub fn dummy_proof() -> Proof {
    dummy_proof_with_protocol("protocol")
}

pub fn dummy_proof_with_protocol(protocol: &str) -> Proof {
    Proof {
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: protocol.to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        schema: Some(dummy_proof_schema().into()),
        claims: Default::default(),
        verifier_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
    }
}

pub fn dummy_key() -> Key {
    Key {
        autogenerated: false,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        public_key: vec![],
        name: "dummy".into(),
        key_reference: None,
        storage_type: "foo".into(),
        key_type: "EDDSA".into(),
        organisation: dummy_organisation(None).into(),
    }
}

pub fn dummy_organisation(id: Option<OrganisationId>) -> Organisation {
    Organisation {
        id: id.unwrap_or(Uuid::new_v4().into()),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        deactivated_at: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
        parent_organisation: None,
        verifier_provider: None,
        verifier_provider_issuer: None,
        configuration: Default::default(),
    }
}

pub fn dummy_proof_schema() -> ProofSchema {
    ProofSchema {
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        deleted_at: None,
        imported_source_url: Some("CORE_URL".to_string()),
        name: "Proof schema".to_string(),
        expire_duration: 100,
        organisation: dummy_organisation(None).into(),
        input_schemas: Default::default(),
    }
}

pub fn dummy_credential_schema() -> CredentialSchema {
    dummy_credential_schema_with_format("format")
}

pub fn dummy_credential_schema_with_format(format: &str) -> CredentialSchema {
    let credential_schema_id = Uuid::new_v4().into();
    CredentialSchema {
        expiration: None,
        ecosystem: None,
        id: credential_schema_id,
        deleted_at: None,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "name".to_string(),
        wallet_attestation: Default::default(),
        imported_source_url: "CORE_URL".to_string(),
        formats: vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_id,
            format: format.into(),
            ecosystem_schema_id: "CredentialSchemaId".to_owned(),
            claim_mappings: Default::default(),
        }]
        .into(),
        batch_size: None,
        claim_schemas: Default::default(),
        organisation: dummy_organisation(None).into(),
        layout_properties: None,
        allow_suspension: true,
        transaction_code: None,
        allow_revocation: true,
        translations: Default::default(),
        embedded_disclosure_policy: None,
    }
}

pub fn dummy_claim_schema() -> ClaimSchema {
    ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "key".to_string(),
        data_type: "data type".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    }
}

pub fn claim_schema(key: &str, data_type: &str, array: bool) -> ClaimSchema {
    ClaimSchema {
        key: key.to_owned(),
        data_type: data_type.to_owned(),
        array,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        ..dummy_claim_schema()
    }
}

pub fn claim_with_schema(schema: &ClaimSchema, path: &str, value: Option<&str>) -> Claim {
    Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: value.map(str::to_owned),
        path: path.to_owned(),
        selectively_disclosable: false,
        schema: schema.clone().into(),
    }
}

/// An issuer single with loaded claims and translated schemas for detail rendering tests.
pub async fn credential_with_claims(
    format: &str,
    claim_schemas: Vec<ClaimSchema>,
    claims: Vec<Claim>,
) -> Credential {
    let schema = crate::mapper::credential_schema_claim::backfill_default_translations(
        CredentialSchema {
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            claim_schemas: claim_schemas.into(),
            allow_revocation: false,
            ..dummy_credential_schema_with_format(format)
        },
        "en",
    )
    .await
    .unwrap();
    let format = schema
        .formats
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let mut credential = dummy_credential_with_exchange("OPENID4VCI_FINAL1");
    let common = credential.common_mut();
    common.created_date = get_dummy_date();
    common.last_modified = get_dummy_date();
    common.state = CredentialStateEnum::Created;
    common.schema = schema.into();
    common.interaction = None;
    CredentialBuilder {
        claims: claims.into(),
        format: Some(format.into()),
        ..credential.into()
    }
    .build()
}

pub fn generic_formatter_capabilities() -> FormatterCapabilities {
    FormatterCapabilities {
        signing_key_algorithms: vec![KeyAlgorithmType::Eddsa],
        features: vec![Features::SupportsTxCode],
        selective_disclosure: vec![],
        issuance_did_methods: vec![
            crate::config::core_config::DidType::Key,
            crate::config::core_config::DidType::Web,
            crate::config::core_config::DidType::Jwk,
            crate::config::core_config::DidType::Tdw,
        ],
        issuance_exchange_protocols: vec![IssuanceProtocolType::OpenId4VciFinal1_0],
        proof_exchange_protocols: vec![VerificationProtocolType::OpenId4VpFinal1_0],
        revocation_methods: vec![RevocationType::BitstringStatusList],
        verification_key_algorithms: vec![KeyAlgorithmType::Eddsa],
        verification_key_storages: vec![KeyStorageType::Internal],
        datatypes: vec!["STRING".into(), "OBJECT".into()],
        forbidden_claim_names: vec![],
        issuance_identifier_types: vec![ConfigIdentifierType::Did],
        verification_identifier_types: vec![ConfigIdentifierType::Did],
        holder_identifier_types: vec![ConfigIdentifierType::Did],
        holder_key_algorithms: vec![
            KeyAlgorithmType::Ecdsa,
            KeyAlgorithmType::Eddsa,
            KeyAlgorithmType::MlDsa,
        ],
        holder_did_methods: vec![
            crate::config::core_config::DidType::Web,
            crate::config::core_config::DidType::Key,
            crate::config::core_config::DidType::Jwk,
            crate::config::core_config::DidType::Tdw,
        ],
    }
}

pub fn dummy_did_document(did: &DidValue) -> DidDocument {
    DidDocument {
        context: serde_json::json!({}),
        id: did.clone(),
        verification_method: vec![DidVerificationMethod {
            id: "did-vm-id".to_string(),
            r#type: "did-vm-type".to_string(),
            controller: "did-vm-controller".to_string(),
            public_key_jwk: dummy_jwk(),
        }],
        authentication: None,
        assertion_method: Some(vec!["did-vm-id".to_string()]),
        key_agreement: None,
        capability_invocation: None,
        capability_delegation: None,
        also_known_as: None,
        service: None,
    }
}

pub fn dummy_jwk() -> PublicJwk {
    PublicJwk::Ec(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
    })
}

pub fn dummy_dcql_query(require_cryptographic_holder_binding: bool) -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".into(),
            format: CredentialFormat::JwtVc(W3cVcMeta {
                type_values: vec![vec!["CredentialSchemaId".to_string()]],
            }),
            claims: None,
            claim_sets: None,
            trusted_authorities: None,
            multiple: false,
            require_cryptographic_holder_binding,
        }],
        credential_sets: None,
    }
}

pub fn dummy_trust_collection() -> TrustCollection {
    TrustCollection {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test-collection".to_string(),
        organisation: dummy_organisation(None).into(),
        deactivated_at: None,
        remote_trust_collection_url: Some(Url::parse("https://example.com").unwrap()),
        ecosystem: "EUDI".into(),
    }
}

pub fn dummy_trust_list_publication() -> TrustListPublication {
    TrustListPublication {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test-publication".to_string(),
        role: TrustListRoleEnum::Issuer,
        r#type: "LOTE".into(),
        metadata: vec![],
        deleted_at: None,
        content: Vec::new(),
        sequence_number: 0,
        organisation: dummy_organisation(None).into(),
        identifier: dummy_identifier().into(),
        key: None,
        certificate: None,
    }
}

/// Build a verifier fixture from an existing credential.
pub fn verifier_credential(
    credential: Credential,
) -> Result<Credential, crate::repository::error::DataLayerError> {
    Ok(CredentialBuilder {
        role: CredentialRole::Verifier,
        r#type: CredentialType::Single,
        ..credential.into()
    }
    .build())
}

pub fn issuer_credential(
    credential: Credential,
) -> Result<Credential, crate::repository::error::DataLayerError> {
    Ok(CredentialBuilder {
        role: CredentialRole::Issuer,
        ..credential.into()
    }
    .build())
}

pub fn holder_single_credential(
    credential: Credential,
) -> Result<Credential, crate::repository::error::DataLayerError> {
    Ok(CredentialBuilder {
        role: CredentialRole::Holder,
        r#type: CredentialType::Single,
        ..credential.into()
    }
    .build())
}

/// Shared fixture inputs for constructing the different credential variants.
/// Missing required relations receive dummy values for unit tests; persistence fixtures
/// must supply relations that exist in their database.
#[derive(Clone, Debug)]
pub struct CredentialBuilder {
    pub common: CredentialCommon,
    pub claims: crate::model::relation::RelatedVec<Claim>,
    pub consumed_at: Option<OffsetDateTime>,
    pub role: CredentialRole,
    pub r#type: CredentialType,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub issuer_identifier: Option<crate::model::relation::Related<Identifier>>,
    pub issuer_certificate: Option<crate::model::relation::Related<Certificate>>,
    pub holder_identifier: Option<crate::model::relation::Related<Identifier>>,
    pub key: Option<crate::model::relation::Related<Key>>,
    pub credential_blob_id: Option<shared_types::BlobId>,
    pub wallet_key_attestation_blob_id: Option<shared_types::BlobId>,
    pub wallet_instance_attestation_blob_id: Option<shared_types::BlobId>,
    pub webhook_url: Option<String>,
    pub embedded_disclosure_policy: Option<String>,
    pub subscriber_information: Option<String>,
    pub parent: Option<crate::model::relation::Related<Credential>>,
    pub format: Option<crate::model::relation::Related<CredentialSchemaFormat>>,
}

impl From<Credential> for CredentialBuilder {
    fn from(value: Credential) -> Self {
        let (issuer_identifier, issuer_certificate, holder_identifier) = match &value {
            Credential::IssuerSingle {
                issuer, credential, ..
            }
            | Credential::IssuerBatchItem {
                issuer, credential, ..
            } => (
                Some(&issuer.identifier),
                issuer.certificate.as_ref(),
                credential.holder_identifier.as_ref(),
            ),
            Credential::IssuerBatchParent { issuer, .. } => {
                (Some(&issuer.identifier), issuer.certificate.as_ref(), None)
            }
            Credential::HolderSingle { credential, .. }
            | Credential::HolderBatchItem { credential, .. } => (
                Some(&credential.issuer.identifier),
                credential.issuer.certificate.as_ref(),
                credential
                    .binding
                    .as_ref()
                    .map(|binding| &binding.identifier),
            ),
            Credential::Verifier { verifier_data, .. } => (
                Some(&verifier_data.issuer.identifier),
                verifier_data.issuer.certificate.as_ref(),
                verifier_data.holder_identifier.as_ref(),
            ),
            Credential::HolderBatchParent { .. } => (None, None, None),
        };
        let issuer_credential = value.issuer_credential().ok();
        let holder = value.holder().ok().map(|view| view.data);
        let binding = holder.and_then(|holder| holder.binding.as_ref());
        Self {
            common: value.common().clone(),
            claims: match &value {
                Credential::IssuerSingle { claims, .. }
                | Credential::IssuerBatchParent { claims, .. } => claims.clone(),
                Credential::HolderSingle { credential, .. }
                | Credential::HolderBatchItem { credential, .. } => credential.claims.clone(),
                Credential::Verifier { verifier_data, .. } => verifier_data.claims.clone(),
                Credential::IssuerBatchItem { .. } | Credential::HolderBatchParent { .. } => {
                    Default::default()
                }
            },
            consumed_at: match &value {
                Credential::HolderBatchItem { consumed_at, .. } => *consumed_at,
                _ => None,
            },
            role: value.role(),
            r#type: value.r#type(),
            suspend_end_date: value.suspend_end_date(),
            issuer_identifier: issuer_identifier.cloned(),
            issuer_certificate: issuer_certificate.cloned(),
            holder_identifier: holder_identifier.cloned(),
            key: value
                .issuer()
                .ok()
                .map(|issuer| issuer.data.signing_key.clone())
                .or_else(|| binding.map(|binding| binding.key.clone())),
            credential_blob_id: value.credential_blob_id(),
            wallet_key_attestation_blob_id: issuer_credential
                .as_ref()
                .and_then(|issuer| issuer.data.wallet_key_attestation_blob_id),
            wallet_instance_attestation_blob_id: issuer_credential
                .and_then(|issuer| issuer.data.wallet_instance_attestation_blob_id),
            webhook_url: match &value {
                Credential::IssuerSingle { webhook_url, .. }
                | Credential::IssuerBatchParent { webhook_url, .. } => webhook_url.clone(),
                _ => None,
            },
            embedded_disclosure_policy: holder
                .and_then(|holder| holder.embedded_disclosure_policy.clone()),
            subscriber_information: match &value {
                Credential::IssuerSingle {
                    subscriber_information,
                    ..
                }
                | Credential::IssuerBatchParent {
                    subscriber_information,
                    ..
                } => subscriber_information.clone(),
                _ => None,
            },
            parent: value.parent().cloned(),
            format: value.format().cloned(),
        }
    }
}

impl CredentialBuilder {
    pub fn build(self) -> Credential {
        use crate::model::credential::{
            HolderBinding, HolderCredentialData, IssuerCredentialData, IssuerData, IssuerIdentity,
            VerifierCredentialData,
        };
        if self.role == CredentialRole::Holder && self.r#type == CredentialType::BatchParent {
            return Credential::HolderBatchParent {
                common: self.common,
            };
        }
        let issuer = IssuerIdentity {
            identifier: self
                .issuer_identifier
                .unwrap_or_else(|| dummy_identifier().into()),
            certificate: self.issuer_certificate,
        };
        if self.role == CredentialRole::Issuer && self.r#type == CredentialType::BatchParent {
            return Credential::IssuerBatchParent {
                common: self.common,
                issuer: IssuerData {
                    identifier: issuer.identifier,
                    certificate: issuer.certificate,
                    signing_key: self.key.unwrap_or_else(|| dummy_key().into()),
                },
                claims: self.claims,
                webhook_url: self.webhook_url,
                subscriber_information: self.subscriber_information,
                suspend_end_date: self.suspend_end_date,
            };
        }
        let format = self.format.unwrap_or_else(|| {
            CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: self.common.created_date,
                last_modified: self.common.last_modified,
                credential_schema_id: self.common.schema.id(),
                format: "JWT".into(),
                ecosystem_schema_id: "test".into(),
                claim_mappings: Default::default(),
            }
            .into()
        });
        if self.role == CredentialRole::Verifier {
            assert_eq!(
                self.r#type,
                CredentialType::Single,
                "verifier fixtures must be single credentials"
            );
            return Credential::Verifier {
                common: self.common,
                verifier_data: VerifierCredentialData {
                    issuer,
                    format,
                    claims: self.claims,
                    holder_identifier: self.holder_identifier,
                },
            };
        }
        let parent = self.parent.unwrap_or_else(|| {
            let mut common = self.common.clone();
            common.id = Uuid::new_v4().into();
            Credential::HolderBatchParent { common }.into()
        });
        if self.role == CredentialRole::Holder {
            let binding = match (self.holder_identifier, self.key) {
                (None, None) => None,
                (identifier, key) => Some(HolderBinding {
                    identifier: identifier.unwrap_or_else(|| dummy_identifier().into()),
                    key: key.unwrap_or_else(|| dummy_key().into()),
                }),
            };
            let credential = HolderCredentialData {
                issuer,
                format,
                claims: self.claims,
                binding,
                credential_blob_id: self.credential_blob_id,
                embedded_disclosure_policy: self.embedded_disclosure_policy,
            };
            if self.r#type == CredentialType::BatchItem {
                Credential::HolderBatchItem {
                    common: self.common,
                    credential,
                    parent,
                    consumed_at: self.consumed_at,
                }
            } else {
                Credential::HolderSingle {
                    common: self.common,
                    credential,
                }
            }
        } else {
            let issuer = IssuerData {
                identifier: issuer.identifier,
                certificate: issuer.certificate,
                signing_key: self.key.unwrap_or_else(|| dummy_key().into()),
            };
            let credential = IssuerCredentialData {
                format,
                holder_identifier: self.holder_identifier,
                credential_blob_id: self.credential_blob_id,
                wallet_key_attestation_blob_id: self.wallet_key_attestation_blob_id,
                wallet_instance_attestation_blob_id: self.wallet_instance_attestation_blob_id,
                suspend_end_date: self.suspend_end_date,
            };
            if self.r#type == CredentialType::BatchItem {
                Credential::IssuerBatchItem {
                    common: self.common,
                    issuer,
                    credential,
                    parent,
                }
            } else {
                Credential::IssuerSingle {
                    common: self.common,
                    issuer,
                    credential,
                    claims: self.claims,
                    webhook_url: self.webhook_url,
                    subscriber_information: self.subscriber_information,
                }
            }
        }
    }
}

pub fn parsed_credential(
    value: Credential,
) -> crate::provider::credential_formatter::model::ParsedCredential {
    let value = CredentialBuilder::from(value);
    crate::provider::credential_formatter::model::ParsedCredential {
        common: value.common,
        issuer: crate::model::credential::IssuerIdentity {
            identifier: value.issuer_identifier.unwrap(),
            certificate: value.issuer_certificate,
        },
        holder_identifier: value.holder_identifier,
        format: value.format.unwrap(),
        claims: value.claims,
    }
}

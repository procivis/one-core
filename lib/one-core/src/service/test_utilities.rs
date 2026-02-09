#![allow(clippy::unwrap_used)]

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indoc::indoc;
use serde::{Deserialize, Serialize};
use shared_types::{DidValue, OrganisationId};
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

use crate::config::core_config::{
    AppConfig, IdentifierType as ConfigIdentifierType, InputFormat, IssuanceProtocolType,
    KeyAlgorithmType, KeyStorageType, RevocationType, VerificationProtocolType,
};
use crate::model::blob::{Blob, BlobType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, KeyStorageSecurity, LayoutType,
};
use crate::model::did::{Did, DidType};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::ProofSchema;
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
                        leeway: 60
                        embedLayoutProperties: true
            SD_JWT:
                type: 'SD_JWT'
                display: 'format.sdjwt'
                order: 1
                params:
                    public:
                        leeway: 60
                        embedLayoutProperties: true
            SD_JWT_VC:
                type: 'SD_JWT_VC'
                display: 'format.sdjwtvc'
                order: 1
                params:
                    public:
                        leeway: 60
                        embedLayoutProperties: true
            JSON_LD_CLASSIC:
                type: 'JSON_LD_CLASSIC'
                display: 'display'
                order: 2
                params:
                    public:
                        leeway: 60
            PHYSICAL_CARD:
                type: 'PHYSICAL_CARD'
                display: 'format.physicalCard'
                order: 5
            MDOC:
              type: 'MDOC'
              display: 'format.mdoc'
              order: 4
              params:
                public:
                  msoExpiresIn: 259200 # 72h in seconds
                  msoExpectedUpdateIn: 86400 # 24h in seconds
                  msoMinimumRefreshTime: 300 # 5min in seconds
                  leeway: 60
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
        issuanceProtocol:
            OPENID4VCI_DRAFT13:
                display: 'display'
                order: 1
                type: 'OPENID4VCI_DRAFT13'
                params:
                    public:
                        preAuthorizedCodeExpiresIn: 300
                        tokenExpiresIn: 86400
                        refreshExpiresIn: 886400
                        redirectUri:
                            enabled: true
                            allowedSchemes: [ https ]
                    private:
                        encryption: '93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e'
            OPENID4VCI_FINAL1:
                display: 'display.openid4vciFinal1'
                order: 2
                type: 'OPENID4VCI_FINAL1'
                params:
                    public:
                        oauthAttestationLeeway: 60
                        keyAttestationLeeway: 60
                        preAuthorizedCodeExpiresIn: 300
                        tokenExpiresIn: 86400
                        refreshExpiresIn: 886400
                        redirectUri:
                            enabled: true
                            allowedSchemes: [ https ]
                    private:
                        encryption: '93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e'
                        nonce:
                            signingKey: '93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e'
                            expiration: 300
                            leeway: 0
        verificationProtocol:
            OPENID4VP_DRAFT20:
                display: 'display'
                order: 1
                type: 'OPENID4VP_DRAFT20'
                params:
                    public:
                        verifier:
                            supportedClientIdSchemes: [ verifier_attestation, redirect_uri, did ]
                        holder:
                            supportedClientIdSchemes: [ redirect_uri, verifier_attestation, did ]
                        redirectUri:
                            enabled: true
                            allowedSchemes: [ https ]
            OPENID4VP_DRAFT25:
                display: 'display'
                order: 2
                type: 'OPENID4VP_DRAFT25'
                params:
                    public:
                        verifier:
                            supportedClientIdSchemes: [ verifier_attestation, redirect_uri, did ]
                        holder:
                            supportedClientIdSchemes: [ redirect_uri, verifier_attestation, did ]
                        redirectUri:
                            enabled: true
                            allowedSchemes: [ https ]
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
            mock:
                display: 'revocation.mock'
                order: 0
                type: 'NONE'
                params: null
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
        trustManagement:
              SIMPLE_TRUST_LIST:
                  display: 'trustManagement.simpleTrustList'
                  type: 'SIMPLE_TRUST_LIST'
                  order: 1
                  enabled: true
                  params:
                      public:
                          enablePublishing: true
                          proofOfPossessionLeeway: 60
        cacheEntities: {}
        blobStorage: {}
        walletProvider: {}
        credentialIssuer: {}
        verificationEngagement:
            QR_CODE:
                display: verificationEngagement.qrCode
                order: 1
                enabled: true
        certificateValidation:
            leeway: 60
        signer: {}
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

    Credential {
        id: credential_id,
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: exchange.to_owned(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Pending,
        suspend_end_date: None,
        profile: None,
        claims: Some(vec![Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            value: Some("claim value".to_string()),
            path: "key".to_string(),
            selectively_disclosable: false,
            schema: Some(ClaimSchema {
                id: claim_schema_id,
                key: "key".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
                metadata: false,
            }),
        }]),
        issuer_identifier: Some(Identifier {
            did: Some(dummy_did()),
            ..dummy_identifier()
        }),
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "schema".to_string(),
            key_storage_security: Some(KeyStorageSecurity::Basic),
            format: "format".into(),
            imported_source_url: "CORE_URL".to_string(),
            revocation_method: Some("revocation method".into()),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: claim_schema_id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: false,
                    metadata: false,
                },
                required: true,
            }]),
            organisation: Some(dummy_organisation(None)),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            data: Some(b"interaction data".to_vec()),
            organisation: None,
            nonce_id: None,
            interaction_type: InteractionType::Issuance,
            expires_at: None,
        }),
        key: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
    }
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
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "INTERNAL".to_string(),
        keys: None,
        organisation: Some(dummy_organisation(None)),
        deactivated: false,
        log: None,
    }
}

pub fn dummy_identifier() -> Identifier {
    Identifier {
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
    }
}

pub fn dummy_proof() -> Proof {
    dummy_proof_with_protocol("protocol")
}

pub fn dummy_proof_with_protocol(protocol: &str) -> Proof {
    Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: protocol.to_string(),
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
            imported_source_url: Some("CORE_URL".to_string()),
            deleted_at: None,
            name: "dummy".to_string(),
            expire_duration: 0,
            organisation: Some(dummy_organisation(None)),
            input_schemas: None,
        }),
        claims: None,
        verifier_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    }
}

pub fn dummy_key() -> Key {
    Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "dummy".into(),
        key_reference: None,
        storage_type: "foo".into(),
        key_type: "EDDSA".into(),
        organisation: None,
    }
}

pub fn dummy_organisation(id: Option<OrganisationId>) -> Organisation {
    let id = id.unwrap_or(Uuid::new_v4().into());
    Organisation {
        name: format!("{id}"),
        id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deactivated_at: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
    }
}

pub fn dummy_proof_schema() -> ProofSchema {
    ProofSchema {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        imported_source_url: Some("CORE_URL".to_string()),
        name: "Proof schema".to_string(),
        expire_duration: 100,
        organisation: None,
        input_schemas: None,
    }
}

pub fn dummy_credential_schema() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        key_storage_security: None,
        imported_source_url: "CORE_URL".to_string(),
        format: "format".into(),
        revocation_method: Some("mock".into()),
        claim_schemas: None,
        organisation: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
        requires_wallet_instance_attestation: false,
        transaction_code: None,
    }
}

pub fn dummy_claim_schema() -> ClaimSchema {
    ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "key".to_string(),
        data_type: "data type".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    }
}

pub fn generic_formatter_capabilities() -> FormatterCapabilities {
    FormatterCapabilities {
        signing_key_algorithms: vec![KeyAlgorithmType::Eddsa],
        features: vec![Features::SupportsTxCode],
        allowed_schema_ids: vec![],
        ecosystem_schema_ids: vec![],
        selective_disclosure: vec![],
        issuance_did_methods: vec![
            crate::config::core_config::DidType::Key,
            crate::config::core_config::DidType::Web,
            crate::config::core_config::DidType::Jwk,
            crate::config::core_config::DidType::WebVh,
        ],
        issuance_exchange_protocols: vec![
            IssuanceProtocolType::OpenId4VciDraft13,
            IssuanceProtocolType::OpenId4VciFinal1_0,
        ],
        proof_exchange_protocols: vec![
            VerificationProtocolType::OpenId4VpDraft20,
            VerificationProtocolType::OpenId4VpDraft25,
            VerificationProtocolType::OpenId4VpFinal1_0,
        ],
        revocation_methods: vec![
            RevocationType::None,
            RevocationType::BitstringStatusList,
            RevocationType::Lvvc,
        ],
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
            crate::config::core_config::DidType::WebVh,
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

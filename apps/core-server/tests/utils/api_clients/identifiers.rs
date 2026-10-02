use core_server::endpoint::trust_list_publication::dto::TrustListRoleRestEnum;
use serde_json::json;
use shared_types::{CertificateId, IdentifierId, KeyId, OrganisationId};

use super::{HttpClient, Response};

pub struct IdentifiersApi {
    pub client: HttpClient,
}

impl IdentifiersApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create_did_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
    ) -> Response {
        let did_name = format!("did-{name}");
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "did": {
                      "keys": {
                        "assertionMethod": [
                          key_id
                        ],
                        "authentication": [
                          key_id
                        ],
                        "capabilityDelegation": [
                          key_id
                        ],
                        "capabilityInvocation": [
                          key_id
                        ],
                        "keyAgreement": [
                          key_id
                        ]
                      },
                      "method": "KEY",
                      "name": did_name,
                      "params": {}
                    },
                    "organisationId": organisation_id
                }),
            )
            .await
    }

    pub async fn create_deprecated_key_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "keyId": key_id,
                    "organisationId": organisation_id
                }),
            )
            .await
    }

    pub async fn create_key_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "key": {
                        "keyId": key_id,
                    },
                    "organisationId": organisation_id
                }),
            )
            .await
    }

    pub async fn create_certificate_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
        chain: &str,
        roles: &[&str],
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "organisationId": organisation_id,
                    "certificates": [{
                        "chain": chain,
                        "keyId": key_id,
                        "roles": roles
                    }]
                }),
            )
            .await
    }

    pub async fn create_certificate_identifier_multiple_certs(
        &self,
        name: &str,
        organisation_id: OrganisationId,
        certs: &[(KeyId, &str)],
        roles: &[&str],
    ) -> Response {
        let certs: Vec<_> = certs
            .iter()
            .map(|(key_id, chain)| {
                json!({
                    "chain": chain,
                    "keyId": key_id,
                    "roles": roles
                })
            })
            .collect();
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "organisationId": organisation_id,
                    "certificates": certs
                }),
            )
            .await
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn create_certificate_identifier_ca_signed(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
        ca_identifier_id: IdentifierId,
        common_name: &str,
        signer: &str,
        profile: &str,
        roles: &[&str],
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "organisationId": organisation_id,
                    "certificates": [{
                        "keyId": key_id,
                        "roles": roles,
                        "content": {
                            "certificateAuthority": {
                                "identifierId": ca_identifier_id
                            },
                            "subject": {
                                "commonName": common_name
                            },
                            "profile": profile,
                            "signer": signer
                        }
                    }]
                }),
            )
            .await
    }

    pub async fn create_certificate_authority_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
        chain: &str,
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "organisationId": organisation_id,
                    "certificateAuthorities": [{
                        "chain": chain,
                        "keyId": key_id
                    }]
                }),
            )
            .await
    }

    pub async fn create_certificate_authority_identifier_self_signed(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
        common_name: &str,
        signer: &str,
        issuer_alternative_name: Option<&str>,
    ) -> Response {
        let issuer_alternative_name = issuer_alternative_name.map(|name| {
            json!({
                "type": "URI",
                "name": name
            })
        });
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "organisationId": organisation_id,
                    "certificateAuthorities": [{
                        "keyId": key_id,
                        "selfSigned": {
                            "content": {
                                "subject": {
                                    "commonName": common_name,
                                },
                                "issuerAlternativeName": issuer_alternative_name
                            },
                            "signer": signer
                        },
                    }]
                }),
            )
            .await
    }

    pub async fn try_create_certificate_authority_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "organisationId": organisation_id,
                    "certificateAuthorities": [{
                        "keyId": key_id
                    }]
                }),
            )
            .await
    }

    pub async fn create_remote(&self, body: serde_json::Value) -> Response {
        self.client.post("/api/identifier/v1/remote", body).await
    }

    /// Create a key identifier, optionally with a `logo` (base64 data URI) and
    /// `translations` (`{ "name": {..}, "logoAltText": {..} }`) block.
    pub async fn create_key_identifier_with_options(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
        logo: Option<&str>,
        translations: Option<serde_json::Value>,
    ) -> Response {
        let mut body = json!({
            "name": name,
            "key": { "keyId": key_id },
            "organisationId": organisation_id,
        });
        if let Some(logo) = logo {
            body["logo"] = json!(logo);
        }
        if let Some(translations) = translations {
            body["translations"] = translations;
        }
        self.client.post("/api/identifier/v1", body).await
    }

    /// Create a key identifier with a `trustInformation` entry attached.
    pub async fn create_key_identifier_with_trust_information(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
        trust_information_data: &str,
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!({
                    "name": name,
                    "key": { "keyId": key_id },
                    "organisationId": organisation_id,
                    "trustInformation": [{
                        "data": trust_information_data,
                        "type": "REGISTRATION_CERTIFICATE",
                    }],
                }),
            )
            .await
    }

    pub async fn get(&self, id: &IdentifierId) -> Response {
        self.client.get(&format!("/api/identifier/v1/{id}")).await
    }

    pub async fn delete(&self, id: &IdentifierId) -> Response {
        self.client
            .delete(&format!("/api/identifier/v1/{id}"))
            .await
    }

    pub async fn patch(&self, id: &IdentifierId, body: serde_json::Value) -> Response {
        self.client
            .patch(&format!("/api/identifier/v1/{id}"), body)
            .await
    }

    pub async fn list(
        &self,
        organisation_id: &OrganisationId,
        additional_filters: Option<String>,
    ) -> Response {
        let mut path =
            format!("/api/identifier/v1?page=0&pageSize=30&organisationId={organisation_id}");
        if let Some(additional_filters) = additional_filters {
            path.push('&');
            path.push_str(&additional_filters);
        }
        self.client.get(&path).await
    }

    pub async fn list_by_key_storage_type(
        &self,
        key_storage_type: &str,
        organisation_id: OrganisationId,
    ) -> Response {
        self.client.get(
            &format!("/api/identifier/v1?page=0&pageSize=30&keyStorages%5B%5D={key_storage_type}&organisationId={organisation_id}")).await
    }

    pub async fn resolve_trust_entries(
        &self,
        identifiers: &[IdentifierId],
        roles: Option<&[TrustListRoleRestEnum]>,
        trust_collection_ids: Option<&[shared_types::TrustCollectionId]>,
    ) -> Response {
        let mut body = json!({
            "identifiers": identifiers,
        });
        if let Some(roles) = roles {
            body["roles"] = json!(roles);
        }
        if let Some(trust_collection_ids) = trust_collection_ids {
            body["trustCollectionIds"] = json!(trust_collection_ids);
        }

        self.client
            .post("/api/identifier/v1/resolve-trust-entries", body)
            .await
    }

    pub async fn add_certificates(
        &self,
        identifier_id: &IdentifierId,
        certificates: serde_json::Value,
    ) -> Response {
        self.client
            .post(
                &format!("/api/identifier/v1/{identifier_id}/certificate"),
                json!({ "certificates": certificates }),
            )
            .await
    }

    pub async fn delete_certificate(
        &self,
        identifier_id: &IdentifierId,
        certificate_id: &CertificateId,
    ) -> Response {
        self.client
            .delete(&format!(
                "/api/identifier/v1/{identifier_id}/certificate/{certificate_id}"
            ))
            .await
    }

    pub async fn add_certificate_authorities(
        &self,
        identifier_id: &IdentifierId,
        certificate_authorities: serde_json::Value,
    ) -> Response {
        self.client
            .post(
                &format!("/api/identifier/v1/{identifier_id}/certificate-authority"),
                json!({ "certificateAuthorities": certificate_authorities }),
            )
            .await
    }

    pub async fn delete_certificate_authority(
        &self,
        identifier_id: &IdentifierId,
        certificate_authority_id: &CertificateId,
    ) -> Response {
        self.client
            .delete(&format!(
                "/api/identifier/v1/{identifier_id}/certificate-authority/{certificate_authority_id}"
            ))
            .await
    }
}

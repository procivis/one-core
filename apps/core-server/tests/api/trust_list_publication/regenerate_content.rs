use core_server::endpoint::trust_list_publication::dto::TrustListRoleRestEnum;
use one_core::model::identifier::{Identifier, IdentifierData};
use one_core::model::trust_list_publication::TrustListPublication;
use one_core::proto::jwt::Jwt;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyUsagePurpose};
use serde_json::{Value, json};
use shared_types::CertificateId;
use similar_asserts::assert_eq;

use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};
use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::ecdsa_testing_params;

fn published_certificates(publication: &TrustListPublication) -> Vec<Value> {
    let content = std::str::from_utf8(&publication.content).unwrap();
    let jwt = Jwt::<Value>::decompose_token(content).unwrap();
    jwt.payload.custom["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]
        ["ServiceInformation"]["ServiceDigitalIdentity"]["X509Certificates"]
        .as_array()
        .unwrap()
        .clone()
}

struct Fixture {
    context: TestContext,
    identifier: Identifier,
    publications: Vec<TrustListPublication>,
}

impl Fixture {
    async fn new(is_ca: bool) -> Self {
        let (context, organisation, identifier, ..) = if is_ca {
            TestContext::new_with_ca_identifier(None).await
        } else {
            TestContext::new_with_certificate_identifier(None).await
        };
        let mut publications = Vec::new();
        for name in ["first", "second", "unrelated"] {
            let response = context
                .api
                .trust_list_publication
                .create_trust_list_publication(CreateTrustListPublicationTestParams {
                    name,
                    role: TrustListRoleRestEnum::PidProvider,
                    r#type: "LOTE_PUBLISHER".into(),
                    identifier_id: identifier.id,
                    organisation_id: organisation.id,
                    key_id: None,
                    certificate_id: None,
                    params: None,
                })
                .await;
            assert_eq!(response.status(), 201);
            let id = response.json_value().await["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            if name != "unrelated" {
                let response = context
                    .api
                    .trust_list_publication
                    .create_trust_entry(id, identifier.id, None)
                    .await;
                assert_eq!(response.status(), 201);
            }
            publications.push(context.db.trust_list_publications.get(id).await.unwrap());
        }
        Self {
            context,
            identifier,
            publications,
        }
    }

    fn is_ca(&self) -> bool {
        matches!(
            self.identifier.data,
            IdentifierData::CertificateAuthority(_)
        )
    }

    async fn add_certificate(&self) -> CertificateId {
        let organisation = self.identifier.organisation.as_ref().await.unwrap();
        let key = self
            .context
            .db
            .keys
            .create(&organisation, ecdsa_testing_params())
            .await;
        let mut ca_params = CertificateParams::default();
        let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);
        let mut params = CertificateParams::default();
        params.serial_number = Some(42.into());
        if self.is_ca() {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        }
        let cert = create_cert(&mut params, ecdsa::Key, &ca_issuer, &ca_params);
        let mut request =
            json!([{ "keyId": key.id, "chain": format!("{}{}", cert.pem(), ca_cert.pem()) }]);
        let api = &self.context.api.identifiers;
        let response = if self.is_ca() {
            api.add_certificate_authorities(&self.identifier.id, request)
                .await
        } else {
            request[0]["roles"] = json!(["ASSERTION_METHOD"]);
            api.add_certificates(&self.identifier.id, request).await
        };
        assert_eq!(response.status(), 201);
        response.json_value().await["ids"][0]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    async fn remove_certificate(&self, id: CertificateId) {
        let api = &self.context.api.identifiers;
        let response = if self.is_ca() {
            api.delete_certificate_authority(&self.identifier.id, &id)
                .await
        } else {
            api.delete_certificate(&self.identifier.id, &id).await
        };
        assert_eq!(response.status(), 204);
    }

    async fn assert_regenerated(&self, sequence_increase: u32, certificate_count: usize) {
        // Inspect persisted content before any content GET can refresh it.
        for original in &self.publications {
            let updated = self
                .context
                .db
                .trust_list_publications
                .get(original.id)
                .await
                .unwrap();
            if original.name == "unrelated" {
                assert_eq!(updated.sequence_number, original.sequence_number);
                assert_eq!(updated.content, original.content);
                continue;
            }
            assert_eq!(
                updated.sequence_number,
                original.sequence_number + sequence_increase
            );
            assert_eq!(published_certificates(&updated).len(), certificate_count);
            if certificate_count == 1 {
                assert_eq!(
                    published_certificates(&updated),
                    published_certificates(original)
                );
            }
        }
    }
}

#[rstest::rstest]
#[case::certificate(false)]
#[case::certificate_authority(true)]
#[tokio::test]
async fn adding_certificate_regenerates_all_publications(#[case] is_ca: bool) {
    let fixture = Fixture::new(is_ca).await;

    fixture.add_certificate().await;

    fixture.assert_regenerated(1, 2).await;
}

#[rstest::rstest]
#[case::certificate(false)]
#[case::certificate_authority(true)]
#[tokio::test]
async fn removing_certificate_regenerates_all_publications(#[case] is_ca: bool) {
    let fixture = Fixture::new(is_ca).await;
    let certificate_id = fixture.add_certificate().await;

    fixture.remove_certificate(certificate_id).await;

    fixture.assert_regenerated(2, 1).await;
}

#[tokio::test]
async fn patching_identifier_regenerates_all_publications() {
    let fixture = Fixture::new(false).await;

    let response = fixture
        .context
        .api
        .identifiers
        .patch(
            &fixture.identifier.id,
            json!({
                "translations": { "name": { "en": "Updated identifier" } }
            }),
        )
        .await;

    assert_eq!(response.status(), 204);
    fixture.assert_regenerated(1, 1).await;
}

use one_core::error::ErrorCode;
use one_core::model::blob::BlobType;
use one_core::model::ecosystem::EcosystemOutcomes;
use one_core::model::history::{
    HistoryAction, HistoryErrorMetadata, HistoryMetadata, WalletRelyingPartyMetadata,
};
use one_core::model::interaction::InteractionType;
use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use similar_asserts::assert_eq;
use url::Url;

use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::proofs::TestingProofParams;

const ACCESS_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIC+jCCAp+gAwIBAgIRAQrC1dwJkUxlszrpRjXZv+QwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAwwHQ0EgY2VydDAeFw0yNjA0MDkwODQzMDhaFw0zMTA0MDgwODQzMDha
MGUxCzAJBgNVBAYMAkNIMR0wGwYDVQRRDBRodHRwczovL3NvbWUtdXJsLmNvbTEU
MBIGA1UEAwwLY29tbW9uIG5hbWUxDjAMBgNVBGEMBW9yZ0lkMREwDwYDVQQKDAhP
cmcgbmFtZTAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+jToTZbglVNJlE/Ul
q+9fo4IBsDCCAawwHwYDVR0jBBgwFoAUNyjNsnb8v1K0L0BtEPf0uTxrQuAwRgYD
VR0RBD8wPYYUaHR0cHM6Ly9zb21lLXVyaS5jb22gFAYDVQQUoA0MCys0MTIzNDU2
Nzg5gQ90ZXN0ZXJAdGVzdC5jb20wDgYDVR0PAQH/BAQDAgOIMCUGA1UdJQQeMBwG
CCsGAQUFBwMCBgcogYxdBQEGBgcogbU0BAEGMGIGA1UdHwRbMFkwV6BVoFOGUWh0
dHA6Ly8xMjcuMC4wLjE6NjEzNDYvc3NpL3Jldm9jYXRpb24vdjEvY3JsLzJiYzE2
MjllLWM2YWItNGNlNy1hMTlkLWYwN2Q1M2YwYzU3NzAdBgNVHQ4EFgQUYSDrfq7B
9LW8JqFf8Goypix19fswDwYDVR0TAQH/BAUwAwEBADAUBgNVHSAEDTALMAkGBwQA
i+xAAQEwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzACpkQWQmh0dHA6Ly8xMjcu
MC4wLjE6NjEzNDYvc3NpL2NhL2Q3NzgxNGI1LWIxZGMtNDIwNS1iZDlmLTA5OGE4
ZTRjNDlkZDAKBggqhkjOPQQDAgNJADBGAiEAuS3o1nlzchI4I0ag0qUxpAUD8/ot
qs3spp6Rlr/mP9wCIQDVavmou3AtikpwkUWe+ZM5HbrwAi6k6lt5nxTPk3tf0A==
-----END CERTIFICATE-----"#;

const REGISTRATION_CERT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6InJjLXdycCtqd3QiLCJ4NWMiOlsiTUlJREZqQ0NBc2lnQXdJQkFnSVJBV3k1ak0wVWFVT2toYWdBa0FwLzZmTXdCUVlESzJWd01CTXhFVEFQQmdOVkJBTU1DSEJ5YjJOcGRtbHpNQjRYRFRJMk1EUXhNREEzTlRnek1Wb1hEVE14TURRd09UQTNOVGd6TVZvd2dhTXhDekFKQmdOVkJBWU1Ba0ZVTVVNd1FRWURWUVJSRERwb2RIUndjem92TDNkaGJHeGxkQzF5Wld4NWFXNW5MWEJoY25SNUxYSmxaMmx6ZEhKNUxtUmxkaTV3Y205amFYWnBjeTF2Ym1VdVkyOXRNUmt3RndZRFZRUUREQkJHY21Wa1pYSnBheUJVWlhOMGFXNW5NUnd3R2dZRFZRUmhEQk5PVkZKQlZDMW1jbVZrWlhKcGF5QjBaWE4wTVJZd0ZBWURWUVFLREExR2NtVmtaWEpwYXlCVVpYTjBNQ293QlFZREsyVndBeUVBcTVJY3RqbG5XazVUeGV4WnNXNVhTTysrcTB6b2NHOXZYMk0wak5DdlJZMmpnZ0dlTUlJQm1qQWZCZ05WSFNNRUdEQVdnQlFnQm4zcitNTXpEQ2lseHdjbWJNTVRtdlVqOWpBZUJnTlZIUkVFRnpBVmhoTm9kSFJ3Y3pvdkwzTjFjSEJ2Y25RdVkyOXRNQTRHQTFVZER3RUIvd1FFQXdJRGlEQWxCZ05WSFNVRUhqQWNCZ2dyQmdFRkJRY0RBZ1lIS0lHTVhRVUJCZ1lIS0lHMU5BUUJCakJ0QmdOVkhSOEVaakJrTUdLZ1lLQmVobHhvZEhSd2N6b3ZMMk52Y21VdVpHVjJMbkJ5YjJOcGRtbHpMVzl1WlM1amIyMHZjM05wTDNKbGRtOWpZWFJwYjI0dmRqRXZZM0pzTHpCa05XUXhaak16TFRnellXRXRORFU0WXkxaU1tTmpMV0V5WkRrMU1tVmhNbUppWXpBZEJnTlZIUTRFRmdRVWRUS3JBeWtJcUNJZHBGT1NlRzQ5YlRadFY0b3dEd1lEVlIwVEFRSC9CQVV3QXdFQkFEQVVCZ05WSFNBRURUQUxNQWtHQndRQWkreEFBUUV3YXdZSUt3WUJCUVVIQVFFRVh6QmRNRnNHQ0NzR0FRVUZCekFDcGs4V1RXaDBkSEJ6T2k4dlkyOXlaUzVrWlhZdWNISnZZMmwyYVhNdGIyNWxMbU52YlM5emMya3ZZMkV2TkdWa01USTRNREl0TnpneU15MDBZMk5rTFRsalkyVXRNak0wTURRMk16WTFZVFkwTUFVR0F5dGxjQU5CQUtncDdkUlo2ZnVNa3lqbk5PbFBKdDZTeGZ5L0dQeGJQSUkwWHF5THAvT094U1BoUE4rcmJMMEh6eDFGMzFYWUcwVUZ6TFR4UkRQdmpoaXpQQ0p5L2dBPSIsIk1JSUJUakNDQVFDZ0F3SUJBZ0lVRmhRTjN3U0w3N2xOeWRIYnJFUTBudkFsVm93d0JRWURLMlZ3TUJNeEVUQVBCZ05WQkFNTUNIQnliMk5wZG1sek1CNFhEVEkyTURNeE1EQTVNekF3T0ZvWERUTXhNRE13T1RBNU16QXdPRm93RXpFUk1BOEdBMVVFQXd3SWNISnZZMmwyYVhNd0tqQUZCZ01yWlhBRElRQzZ0SjNZaEZPNHFhYUFicmpmSi9ibElNYmROdm5SSUpCS3BRWTRkNVFQenFObU1HUXdId1lEVlIwakJCZ3dGb0FVSUFaOTYvakRNd3dvcGNjSEptekRFNXIxSS9Zd0RnWURWUjBQQVFIL0JBUURBZ0VHTUIwR0ExVWREZ1FXQkJRZ0JuM3IrTU16RENpbHh3Y21iTU1UbXZVajlqQVNCZ05WSFJNQkFmOEVDREFHQVFIL0FnRUFNQVVHQXl0bGNBTkJBTVZ4c1JhUUl3OGdWSVd5QWNCaEcrVHRvT0NwUnBmZWRoNHU0MUJlaTlzU1k3NEFabm5TUlU1NmtZQjA5TTVKMDVXN2pXWDBSN05JSkVtMStUMm5XQWc9Il19.eyJpYXQiOjE3NzYwNjMzNDYsImV4cCI6MTc3ODY1NTM0NiwibmJmIjoxNzc2MDYzMzQ2LCJzdWIiOiJOVFJDSC1jaC5wcm9jaXZpcyIsImF1ZCI6WyJibGkiLCJibGEiXSwianRpIjoiMDU2ZmY3NTUtZTZjMS00OTBhLTg5N2MtODI4ZmU5N2M4ODJhIiwibmFtZSI6IlNwcmludCBSZXZpZXcgV1JQIiwic3ViX2xuIjoiUHJvY2l2aXMgQUciLCJjb3VudHJ5IjoiQ0giLCJyZWdpc3RyeV91cmkiOiJodHRwczovL3dhbGxldC1yZWx5aW5nLXBhcnR5LXJlZ2lzdHJ5LmRldi5wcm9jaXZpcy1vbmUuY29tLyIsInNydl9kZXNjcmlwdGlvbiI6W1t7ImxhbmciOiJlbiIsInZhbHVlIjoiVGhpcyBpcyBhIHNlcnZpY2UgZGVzY3JpcHRpb24ifV1dLCJlbnRpdGxlbWVudHMiOlsiaHR0cHM6Ly91cmkuZXRzaS5vcmcvMTk0NzUvRW50aXRsZW1lbnQvU2VydmljZV9Qcm92aWRlciJdLCJwcml2YWN5X3BvbGljeSI6Imh0dHBzOi8vcHJvY2l2aXMuY2gvcHJpdmFjeSIsImluZm9fdXJpIjoiaHR0cHM6Ly9wcm9jaXZpcy5jaC8iLCJzdXBlcnZpc29yeV9hdXRob3JpdHkiOnsiZW1haWwiOiJpbmZvQHByb2NpdmlzLmNoIiwicGhvbmUiOiIrNDEgNDQgNTIzIDY1IDM1IiwidXJpIjoid3d3LnByb2NpdmlzLmNoIn0sInBvbGljeV9pZCI6WyIwLjQuMC4xOTQ3NS4zLjEiXSwiY2VydGlmaWNhdGVfcG9saWN5IjoiaHR0cHM6Ly90ZXN0LmNlcnRpZmljYXRlL3BvbGljeSIsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJ1cmkiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL3Jldm9jYXRpb24vdjEvbGlzdC80NWM5MjZiZi1hNDUyLTRiMTctYmRhMS03OGZmM2I5ZGQxMjkiLCJpZHgiOiIyIn19LCJwcm92aWRlc19hdHRlc3RhdGlvbnMiOltdLCJjcmVkZW50aWFscyI6W3siZm9ybWF0IjoiZGMrc2Qtand0IiwibWV0YSI6eyJ2Y3RfdmFsdWVzIjpbInVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSJdfSwiY2xhaW0iOlt7InBhdGgiOlsiJC5naXZlbl9uYW1lIl0sInZhbHVlcyI6W119XX1dLCJwdXJwb3NlIjpbeyJsYW5nIjoiZW4iLCJ2YWx1ZSI6IlRoaXMgaXMgdGhlIGludGVuZGVkIHVzZSJ9XSwiaW50ZW5kZWRfdXNlX2lkIjoiZjA0ZmU2MjAtMjU4OC00NTFlLWI5OWMtNjJmYjUwZjFlZGQ2Iiwic3VwcG9ydF91cmkiOiJodHRwczovL3Byb2NpdmlzLmNoLyJ9.Amk_SIsm-o-xlAa-gQBwu9kc5iQ6O_3IG-lmuqZ4Ku6WwGcbjgOmYfK4OZN3WHP5XdvFTvQu0AUveEvtJ796DA";
#[tokio::test]
async fn test_get_proof_trust_detail_success() {
    // GIVEN
    let (context, organisation, identifier, _, key) =
        TestContext::new_with_certificate_identifier(None).await;

    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Verification,
            Default::default(),
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Requested,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(key),
                interaction: Some(interaction),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
        .await;

    let ac_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(ACCESS_CERT.as_bytes().to_vec()),
            r#type: Some(BlobType::HistoryMetadata),
            ..Default::default()
        })
        .await;
    let rc_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(REGISTRATION_CERT.as_bytes().to_vec()),
            r#type: Some(BlobType::HistoryMetadata),
            ..Default::default()
        })
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                entity_id: Some(proof.id.into()),
                action: Some(HistoryAction::WrpAcReceived),
                metadata_blob_id: Some(ac_blob.id),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                entity_id: Some(proof.id.into()),
                action: Some(HistoryAction::WrpRcReceived),
                metadata_blob_id: Some(rc_blob.id),
                ..Default::default()
            },
        )
        .await;

    let mut outcomes = EcosystemOutcomes::validated("EUDI".into());
    outcomes.record(
        "OTHER".into(),
        Err(HistoryErrorMetadata {
            error_code: ErrorCode::BR_0477,
            message: "not on the trust list".to_string(),
        }),
    );
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                entity_id: Some(proof.id.into()),
                action: Some(HistoryAction::EcosystemsResolved),
                metadata: Some(HistoryMetadata::EcosystemsResolved(outcomes)),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get_trust_detail(&proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let rp_data = json!({
        "country": "CH",
        "email": "tester@test.com",
        "identifier": "NTRCH-ch.procivis",
        "isPublicSector": false,
        "name": "Sprint Review WRP",
        "phone": "+4123456789",
        "serviceDescription": [
          {
            "en": "This is a service description"
          }
        ],
        "supervisoryAuthority": {
          "email": "info@procivis.ch",
          "phone": "+41 44 523 65 35",
          "uri": "www.procivis.ch"
        },
        "supportUrl": "https://procivis.ch/",
        "infoUrl": "https://procivis.ch/",
        "privacyPolicyUrl": "https://procivis.ch/privacy"
    });

    assert_eq!(
        resp,
        json!({
            "ecosystem": "EUDI",
            "ecosystemErrors": {
                "OTHER": {
                    "result": "NOT_TRUSTED",
                    "error": { "code": "BR_0477", "message": "not on the trust list" }
                }
            },
            "eudiEcosystem": rp_data,
            "verifier": rp_data
        })
    );
}

// Hand-crafted national registry WRP JWT (header.payload.signature, unsigned - the signature
// segment is never verified by `Jwt::decompose_token`). Decoded payload:
// {
//   "iat": 1776063346,
//   "sub": "NTRCH-nr.procivis",
//   "data": {
//     "tradeName": "National Registry WRP",
//     "supportURI": ["https://procivis.ch/nr-support"],
//     "srvDescription": [{"lang": "en", "content": "NR service description"}],
//     "intendedUse": [{
//       "purpose": [{"lang": "en", "content": "Age verification"}],
//       "privacyPolicy": [{
//         "type": "http://data.europa.eu/eudi/policy/privacy-policy",
//         "policyURI": "https://procivis.ch/nr-privacy"
//       }],
//       "createdAt": "2026-01-01T00:00:00Z",
//       "revokedAt": null,
//       "credential": [{"format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}],
//       "intendedUseIdentifier": "use-1"
//     }],
//     "entitlement": [],
//     "supervisoryAuthority": {
//       "legalPerson": {"legalName": ["National Supervisory Authority"]},
//       "naturalPerson": null,
//       "country": "CH",
//       "email": ["supervisory@example.com"],
//       "phone": ["+41000000000"],
//       "infoURI": ["https://supervisory.example.com"]
//     },
//     "registryURI": "https://procivis.ch/registry",
//     "country": "CH",
//     "email": ["nr-contact@procivis.ch"],
//     "phone": ["+41111111111"],
//     "infoURI": ["https://procivis.ch/nr-info"]
//   }
// }
const NATIONAL_REGISTRY_JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IndycC1ucitqd3QifQ.eyJpYXQiOjE3NzYwNjMzNDYsInN1YiI6Ik5UUkNILW5yLnByb2NpdmlzIiwiZGF0YSI6eyJ0cmFkZU5hbWUiOiJOYXRpb25hbCBSZWdpc3RyeSBXUlAiLCJzdXBwb3J0VVJJIjpbImh0dHBzOi8vcHJvY2l2aXMuY2gvbnItc3VwcG9ydCJdLCJzcnZEZXNjcmlwdGlvbiI6W3sibGFuZyI6ImVuIiwiY29udGVudCI6Ik5SIHNlcnZpY2UgZGVzY3JpcHRpb24ifV0sImludGVuZGVkVXNlIjpbeyJwdXJwb3NlIjpbeyJsYW5nIjoiZW4iLCJjb250ZW50IjoiQWdlIHZlcmlmaWNhdGlvbiJ9XSwicHJpdmFjeVBvbGljeSI6W3sidHlwZSI6Imh0dHA6Ly9kYXRhLmV1cm9wYS5ldS9ldWRpL3BvbGljeS9wcml2YWN5LXBvbGljeSIsInBvbGljeVVSSSI6Imh0dHBzOi8vcHJvY2l2aXMuY2gvbnItcHJpdmFjeSJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMS0wMVQwMDowMDowMFoiLCJyZXZva2VkQXQiOm51bGwsImNyZWRlbnRpYWwiOlt7ImZvcm1hdCI6Im1zb19tZG9jIiwibWV0YSI6eyJkb2N0eXBlX3ZhbHVlIjoib3JnLmlzby4xODAxMy41LjEubURMIn19XSwiaW50ZW5kZWRVc2VJZGVudGlmaWVyIjoidXNlLTEifV0sImVudGl0bGVtZW50IjpbXSwic3VwZXJ2aXNvcnlBdXRob3JpdHkiOnsibGVnYWxQZXJzb24iOnsibGVnYWxOYW1lIjpbIk5hdGlvbmFsIFN1cGVydmlzb3J5IEF1dGhvcml0eSJdfSwibmF0dXJhbFBlcnNvbiI6bnVsbCwiY291bnRyeSI6IkNIIiwiZW1haWwiOlsic3VwZXJ2aXNvcnlAZXhhbXBsZS5jb20iXSwicGhvbmUiOlsiKzQxMDAwMDAwMDAwIl0sImluZm9VUkkiOlsiaHR0cHM6Ly9zdXBlcnZpc29yeS5leGFtcGxlLmNvbSJdfSwicmVnaXN0cnlVUkkiOiJodHRwczovL3Byb2NpdmlzLmNoL3JlZ2lzdHJ5IiwiY291bnRyeSI6IkNIIiwiZW1haWwiOlsibnItY29udGFjdEBwcm9jaXZpcy5jaCJdLCJwaG9uZSI6WyIrNDExMTExMTExMTEiXSwiaW5mb1VSSSI6WyJodHRwczovL3Byb2NpdmlzLmNoL25yLWluZm8iXX19.ZHVtbXktc2lnbmF0dXJl";

#[tokio::test]
async fn test_get_proof_trust_detail_national_registry_success() {
    // GIVEN a verification resolved via the National Registry (not a registration certificate),
    // where the matched intended use's privacy policy URL was captured and stored on the
    // WrpNrReceived history entry's metadata (as `resolve_trust` does at request time)
    let (context, organisation, identifier, _, key) =
        TestContext::new_with_certificate_identifier(None).await;

    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Verification,
            Default::default(),
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Requested,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(key),
                interaction: Some(interaction),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
        .await;

    let ac_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(ACCESS_CERT.as_bytes().to_vec()),
            r#type: Some(BlobType::HistoryMetadata),
            ..Default::default()
        })
        .await;
    let nr_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(NATIONAL_REGISTRY_JWT.as_bytes().to_vec()),
            r#type: Some(BlobType::HistoryMetadata),
            ..Default::default()
        })
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                entity_id: Some(proof.id.into()),
                action: Some(HistoryAction::WrpAcReceived),
                metadata_blob_id: Some(ac_blob.id),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                entity_id: Some(proof.id.into()),
                action: Some(HistoryAction::WrpNrReceived),
                metadata_blob_id: Some(nr_blob.id),
                metadata: Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        privacy_policy_url: Some(
                            Url::parse("https://procivis.ch/nr-privacy").unwrap(),
                        ),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get_trust_detail(&proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let rp_data = json!({
        "country": "CH",
        "email": "tester@test.com",
        "identifier": "NTRCH-nr.procivis",
        "isPublicSector": false,
        "name": "National Registry WRP",
        "phone": "+4123456789",
        "serviceDescription": [
          {
            "en": "NR service description"
          }
        ],
        "supervisoryAuthority": {
          "email": "supervisory@example.com",
          "phone": "+41000000000",
          "uri": "https://supervisory.example.com"
        },
        "supportUrl": "https://procivis.ch/nr-support",
        "infoUrl": "https://procivis.ch/nr-info",
        "privacyPolicyUrl": "https://procivis.ch/nr-privacy"
    });

    assert_eq!(
        resp,
        json!({
            "ecosystem": "EUDI",
            "ecosystemErrors": {},
            "eudiEcosystem": rp_data,
            "verifier": rp_data
        })
    );
}

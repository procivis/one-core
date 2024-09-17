#![cfg_attr(feature = "strict", deny(warnings))]

use std::any::Any;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{middleware, Extension, Router};
use one_core::OneCore;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, info_span, Span};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::dto::response::ErrorResponse;
use crate::endpoint::{
    config, credential, credential_schema, did, did_resolver, history, interaction, jsonld, key,
    misc, organisation, proof, proof_schema, ssi, task, trust_anchor, trust_entity,
};
use crate::middleware::get_http_request_context;
use crate::{build_info, dto, ServerConfig};

pub(crate) struct InternalAppState {
    pub core: OneCore,
    pub config: Arc<ServerConfig>,
}

pub(crate) type AppState = Arc<InternalAppState>;

pub async fn start_server(listener: TcpListener, config: ServerConfig, core: OneCore) {
    listener.set_nonblocking(true).unwrap();

    let config = Arc::new(config);
    let state: AppState = Arc::new(InternalAppState {
        core,
        config: config.to_owned(),
    });

    let addr = listener.local_addr().expect("Invalid TCP listener");
    info!("Starting server at http://{addr}");

    let router = router(state, config);

    axum::serve(
        tokio::net::TcpListener::from_std(listener)
            .expect("failed to convert to tokio TcpListener"),
        router.into_make_service(),
    )
    .await
    .expect("Failed to start axum server");
}

fn router(state: AppState, config: Arc<ServerConfig>) -> Router {
    let openapi_documentation = gen_openapi_documentation();

    let protected = Router::new()
        .route("/api/config/v1", get(config::controller::get_config))
        .route(
            "/api/credential/v1",
            get(credential::controller::get_credential_list)
                .post(credential::controller::post_credential)
                .layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/credential/v1/:id",
            delete(credential::controller::delete_credential)
                .get(credential::controller::get_credential),
        )
        .route(
            "/api/credential/v1/:id/reactivate",
            post(credential::controller::reactivate_credential),
        )
        .route(
            "/api/credential/v1/:id/revoke",
            post(credential::controller::revoke_credential),
        )
        .route(
            "/api/credential/v1/:id/suspend",
            post(credential::controller::suspend_credential),
        )
        .route(
            "/api/credential/v1/:id/share",
            post(credential::controller::share_credential),
        )
        .route(
            "/api/credential/v1/revocation-check",
            post(credential::controller::revocation_check),
        )
        .route(
            "/api/proof-request/v1/:id/share",
            post(proof::controller::share_proof),
        )
        .route(
            "/api/credential-schema/v1/:id",
            delete(credential_schema::controller::delete_credential_schema)
                .get(credential_schema::controller::get_credential_schema),
        )
        .route(
            "/api/credential-schema/v1",
            get(credential_schema::controller::get_credential_schema_list)
                .post(credential_schema::controller::post_credential_schema),
        )
        .route(
            "/api/credential-schema/v1/import",
            post(credential_schema::controller::import_credential_schema),
        )
        .route(
            "/api/credential-schema/v1/:id/share",
            post(credential_schema::controller::share_credential_schema),
        )
        .route(
            "/api/proof-schema/v1/:id",
            delete(proof_schema::controller::delete_proof_schema)
                .get(proof_schema::controller::get_proof_schema_detail),
        )
        .route(
            "/api/proof-schema/v1/:id/share",
            post(proof_schema::controller::share_proof_schema),
        )
        .route(
            "/api/proof-schema/v1/import",
            post(proof_schema::controller::import_proof_schema),
        )
        .route(
            "/api/history/v1",
            get(history::controller::get_history_list),
        )
        .route(
            "/api/history/v1/:id",
            get(history::controller::get_history_entry),
        )
        .route("/api/key/v1/:id", get(key::controller::get_key))
        .route(
            "/api/key/v1/:id/check-certificate",
            post(key::controller::check_certificate),
        )
        .route(
            "/api/key/v1/:id/generate-csr",
            post(key::controller::generate_csr),
        )
        .route(
            "/api/key/v1",
            post(key::controller::post_key).get(key::controller::get_key_list),
        )
        .route(
            "/api/proof-schema/v1",
            get(proof_schema::controller::get_proof_schemas)
                .post(proof_schema::controller::post_proof_schema),
        )
        .route(
            "/api/proof-request/v1",
            post(proof::controller::post_proof).get(proof::controller::get_proofs),
        )
        .route(
            "/api/proof-request/v1/:id",
            get(proof::controller::get_proof_details),
        )
        .route(
            "/api/proof-request/v1/:id/presentation-definition",
            get(proof::controller::get_proof_presentation_definition),
        )
        .route(
            "/api/proof-request/v1/:id/retract",
            post(proof::controller::retract_proof),
        )
        .route(
            "/api/organisation/v1",
            get(organisation::controller::get_organisations)
                .post(organisation::controller::post_organisation),
        )
        .route(
            "/api/organisation/v1/:id",
            get(organisation::controller::get_organisation),
        )
        .route("/api/did/v1/:id", get(did::controller::get_did))
        .route("/api/did/v1/:id", patch(did::controller::update_did))
        .route("/api/did/v1", get(did::controller::get_did_list))
        .route("/api/did/v1", post(did::controller::post_did))
        .route(
            "/api/did-resolver/v1/:didvalue",
            get(did_resolver::controller::resolve_did),
        )
        .route(
            "/api/interaction/v1/handle-invitation",
            post(interaction::controller::handle_invitation),
        )
        .route(
            "/api/interaction/v1/issuance-accept",
            post(interaction::controller::issuance_accept),
        )
        .route(
            "/api/interaction/v1/issuance-reject",
            post(interaction::controller::issuance_reject),
        )
        .route(
            "/api/interaction/v1/presentation-submit",
            post(interaction::controller::presentation_submit),
        )
        .route(
            "/api/interaction/v1/propose-proof",
            post(interaction::controller::propose_proof),
        )
        .route(
            "/api/interaction/v1/presentation-reject",
            post(interaction::controller::presentation_reject),
        )
        .route("/api/task/v1/run", post(task::controller::post_task))
        .route(
            "/api/trust-anchor/v1",
            post(trust_anchor::controller::create_trust_anchor),
        )
        .route(
            "/api/trust-anchor/v1/:id",
            get(trust_anchor::controller::get_trust_anchor),
        )
        .route(
            "/api/trust-anchor/v1",
            get(trust_anchor::controller::get_trust_anchors),
        )
        .route(
            "/api/trust-anchor/v1/:id",
            delete(trust_anchor::controller::delete_trust_anchor),
        )
        .route(
            "/api/trust-entity/v1",
            post(trust_entity::controller::create_trust_entity)
                .get(trust_entity::controller::get_trust_entities),
        )
        .route(
            "/api/trust-entity/v1/:id",
            delete(trust_entity::controller::delete_trust_entity)
                .get(trust_entity::controller::get_trust_entity_details),
        )
        .route(
            "/api/jsonld-context/v1",
            get(jsonld::controller::resolve_jsonld_context),
        )
        .layer(middleware::from_fn(crate::middleware::bearer_check));

    let unprotected = Router::new()
        .route(
            "/ssi/oidc-issuer/v1/:id/.well-known/openid-credential-issuer",
            get(ssi::controller::oidc_get_issuer_metadata),
        )
        .route(
            "/ssi/oidc-issuer/v1/:id/.well-known/openid-configuration",
            get(ssi::controller::oidc_service_discovery),
        )
        .route(
            "/ssi/oidc-issuer/v1/:credential_schema_id/offer/:credential_id",
            get(ssi::controller::oidc_get_credential_offer),
        )
        .route(
            "/ssi/oidc-issuer/v1/:id/token",
            post(ssi::controller::oidc_create_token),
        )
        .route(
            "/ssi/oidc-issuer/v1/:id/credential",
            post(ssi::controller::oidc_create_credential),
        )
        .route(
            "/ssi/oidc-verifier/v1/response",
            post(ssi::controller::oidc_verifier_direct_post).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/ssi/oidc-verifier/v1/:id/presentation-definition",
            get(ssi::controller::oidc_verifier_presentation_definition),
        )
        .route(
            "/ssi/oidc-verifier/v1/:id/client-metadata",
            get(ssi::controller::oidc_client_metadata),
        )
        .route(
            "/ssi/revocation/v1/list/:id",
            get(ssi::controller::get_revocation_list_by_id),
        )
        .route(
            "/ssi/revocation/v1/lvvc/:id",
            get(ssi::controller::get_lvvc_by_credential_id),
        )
        .route(
            "/ssi/did-web/v1/:id/did.json",
            get(ssi::controller::get_did_web_document),
        )
        .route(
            "/ssi/temporary-issuer/v1/connect",
            post(ssi::controller::ssi_issuer_connect),
        )
        .route(
            "/ssi/temporary-issuer/v1/reject",
            post(ssi::controller::ssi_issuer_reject),
        )
        .route(
            "/ssi/temporary-issuer/v1/submit",
            post(ssi::controller::ssi_issuer_submit),
        )
        .route(
            "/ssi/temporary-verifier/v1/connect",
            post(ssi::controller::ssi_verifier_connect),
        )
        .route(
            "/ssi/temporary-verifier/v1/submit",
            post(ssi::controller::ssi_verifier_submit_proof),
        )
        .route(
            "/ssi/temporary-verifier/v1/reject",
            post(ssi::controller::ssi_verifier_reject_proof),
        )
        .route(
            "/ssi/context/v1/:id",
            get(ssi::controller::get_json_ld_context),
        )
        .route(
            "/ssi/schema/v1/:id",
            get(ssi::controller::ssi_get_credential_schema),
        )
        .route(
            "/ssi/proof-schema/v1/:id",
            get(ssi::controller::ssi_get_proof_schema),
        )
        .route(
            "/ssi/trust/v1/:trustAnchorId",
            get(ssi::controller::ssi_get_trust_list),
        );

    let technical_endpoints = Router::new()
        .route("/build-info", get(misc::get_build_info))
        .route("/health", get(misc::health_check))
        .route("/metrics", get(misc::get_metrics));

    Router::new()
        .merge(protected)
        .merge(unprotected)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let context = get_http_request_context(request);
                    info_span!(
                        "http_request",
                        method = context.method,
                        path = context.path,
                        service = "one-core",
                        RequestId = context.request_id,
                        SessionId = context.session_id,
                    )
                })
                .on_request(|request: &Request<_>, _span: &Span| {
                    tracing::debug!(
                        "SERVICE CALL START {} {}",
                        request.method(),
                        request.uri().path()
                    )
                })
                .on_failure(|_, _, _: &_| {}) // override default on_failure handler
                .on_response(|response: &Response<_>, _: Duration, _span: &Span| {
                    tracing::debug!("SERVICE CALL END {}", response.status())
                }),
        )
        .layer(middleware::from_fn(crate::middleware::sentry_layer))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi_documentation))
        .layer(middleware::from_fn(crate::middleware::metrics_counter))
        .merge(technical_endpoints)
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(Extension(config))
        .with_state(state)
}

fn gen_openapi_documentation() -> utoipa::openapi::OpenApi {
    #[derive(OpenApi)]
    #[openapi(
        paths(
            config::controller::get_config,

            organisation::controller::post_organisation,
            organisation::controller::get_organisation,
            organisation::controller::get_organisations,

            credential::controller::delete_credential,
            credential::controller::get_credential,
            credential::controller::get_credential_list,
            credential::controller::post_credential,
            credential::controller::reactivate_credential,
            credential::controller::revoke_credential,
            credential::controller::suspend_credential,
            credential::controller::share_credential,
            credential::controller::revocation_check,

            credential_schema::controller::delete_credential_schema,
            credential_schema::controller::get_credential_schema,
            credential_schema::controller::get_credential_schema_list,
            credential_schema::controller::import_credential_schema,
            credential_schema::controller::post_credential_schema,
            credential_schema::controller::share_credential_schema,

            did::controller::get_did,
            did::controller::get_did_list,
            did::controller::post_did,
            did::controller::update_did,

            did_resolver::controller::resolve_did,

            history::controller::get_history_list,
            history::controller::get_history_entry,

            key::controller::check_certificate,
            key::controller::generate_csr,
            key::controller::get_key,
            key::controller::get_key_list,
            key::controller::post_key,

            proof_schema::controller::post_proof_schema,
            proof_schema::controller::get_proof_schemas,
            proof_schema::controller::get_proof_schema_detail,
            proof_schema::controller::share_proof_schema,
            proof_schema::controller::import_proof_schema,
            proof_schema::controller::delete_proof_schema,

            proof::controller::get_proof_details,
            proof::controller::get_proofs,
            proof::controller::post_proof,
            proof::controller::share_proof,
            proof::controller::get_proof_presentation_definition,
            proof::controller::retract_proof,

            ssi::controller::ssi_verifier_connect,
            ssi::controller::ssi_verifier_submit_proof,
            ssi::controller::ssi_verifier_reject_proof,
            ssi::controller::ssi_issuer_reject,
            ssi::controller::ssi_issuer_connect,
            ssi::controller::ssi_issuer_reject,
            ssi::controller::ssi_issuer_submit,
            ssi::controller::get_lvvc_by_credential_id,
            ssi::controller::get_revocation_list_by_id,
            ssi::controller::get_did_web_document,
            ssi::controller::oidc_get_issuer_metadata,
            ssi::controller::oidc_service_discovery,
            ssi::controller::oidc_get_credential_offer,
            ssi::controller::oidc_create_token,
            ssi::controller::oidc_create_credential,
            ssi::controller::oidc_verifier_direct_post,
            ssi::controller::oidc_verifier_presentation_definition,
            ssi::controller::oidc_client_metadata,
            ssi::controller::get_json_ld_context,
            ssi::controller::ssi_get_credential_schema,
            ssi::controller::ssi_get_proof_schema,
            ssi::controller::ssi_get_trust_list,

            interaction::controller::handle_invitation,
            interaction::controller::issuance_accept,
            interaction::controller::issuance_reject,
            interaction::controller::presentation_submit,
            interaction::controller::presentation_reject,
            interaction::controller::propose_proof,

            task::controller::post_task,

            trust_anchor::controller::create_trust_anchor,
            trust_anchor::controller::get_trust_anchor,
            trust_anchor::controller::get_trust_anchors,
            trust_anchor::controller::delete_trust_anchor,

            trust_entity::controller::create_trust_entity,
            trust_entity::controller::delete_trust_entity,
            trust_entity::controller::get_trust_entity_details,
            trust_entity::controller::get_trust_entities,

            jsonld::controller::resolve_jsonld_context,

            misc::get_build_info,
            misc::health_check,
            misc::get_metrics,
        ),
        components(
            schemas(
                config::dto::ConfigRestDTO,

                organisation::dto::CreateOrganisationRequestRestDTO,
                organisation::dto::CreateOrganisationResponseRestDTO,
                organisation::dto::GetOrganisationDetailsResponseRestDTO,

                credential::dto::CreateCredentialRequestRestDTO,
                credential::dto::CredentialDetailClaimResponseRestDTO,
                credential::dto::CredentialListItemResponseRestDTO,
                credential::dto::CredentialRequestClaimRestDTO,
                credential::dto::GetCredentialResponseRestDTO,
                credential::dto::CredentialDetailSchemaResponseRestDTO,
                credential::dto::CredentialRevocationCheckRequestRestDTO,
                credential::dto::CredentialRevocationCheckResponseRestDTO,
                credential::dto::CredentialStateRestEnum,
                credential::dto::CredentialRoleRestEnum,
                credential::dto::CredentialDetailClaimValueResponseRestDTO,
                credential::dto::SuspendCredentialRequestRestDTO,

                credential_schema::dto::CreateCredentialSchemaRequestRestDTO,
                credential_schema::dto::CredentialClaimSchemaRequestRestDTO,
                credential_schema::dto::CredentialClaimSchemaResponseRestDTO,
                credential_schema::dto::CredentialSchemaResponseRestDTO,
                credential_schema::dto::CredentialSchemaListItemResponseRestDTO,
                credential_schema::dto::WalletStorageTypeRestEnum,
                credential_schema::dto::CredentialSchemaLayoutType,
                credential_schema::dto::CredentialSchemaLayoutPropertiesRestDTO,
                credential_schema::dto::CredentialSchemaBackgroundPropertiesRestDTO,
                credential_schema::dto::CredentialSchemaLogoPropertiesRestDTO,
                credential_schema::dto::CredentialSchemaCodePropertiesRestDTO,
                credential_schema::dto::CredentialSchemaCodeTypeRestEnum,
                credential_schema::dto::CredentialSchemaType,
                credential_schema::dto::CredentialSchemaShareResponseRestDTO,
                credential_schema::dto::ImportCredentialSchemaRequestRestDTO,
                credential_schema::dto::ImportCredentialSchemaRequestSchemaRestDTO,
                credential_schema::dto::ImportCredentialSchemaClaimSchemaRestDTO,
                credential_schema::dto::ImportCredentialSchemaLayoutPropertiesRestDTO,

                did::dto::CreateDidRequestRestDTO,
                did::dto::CreateDidRequestKeysRestDTO,
                did::dto::DidPatchRequestRestDTO,
                did::dto::DidResponseRestDTO,
                did::dto::DidResponseKeysRestDTO,
                did::dto::DidListItemResponseRestDTO,
                did::dto::DidType,

                history::dto::HistoryResponseRestDTO,
                history::dto::HistoryAction,
                history::dto::HistoryEntityType,
                history::dto::HistorySearchEnumRest,
                history::dto::HistoryMetadataRest,

                key::dto::KeyRequestRestDTO,
                key::dto::KeyResponseRestDTO,
                key::dto::KeyListItemResponseRestDTO,
                key::dto::KeyCheckCertificateRequestRestDTO,
                key::dto::KeyGenerateCSRRequestRestDTO,
                key::dto::KeyGenerateCSRRequestProfileRest,
                key::dto::KeyGenerateCSRRequestSubjectRestDTO,
                key::dto::KeyGenerateCSRResponseRestDTO,

                proof::dto::ProofStateRestEnum,
                proof::dto::CreateProofRequestRestDTO,
                proof::dto::ScanToVerifyRequestRestDTO,
                proof::dto::ScanToVerifyBarcodeTypeRestEnum,
                proof::dto::ProofListItemResponseRestDTO,
                proof::dto::ProofDetailResponseRestDTO,
                proof::dto::ProofClaimRestDTO,
                proof::dto::ProofClaimValueRestDTO,
                proof::dto::ProofInputRestDTO,
                proof::dto::PresentationDefinitionResponseRestDTO,
                proof::dto::PresentationDefinitionRequestGroupResponseRestDTO,
                proof::dto::PresentationDefinitionRuleRestDTO,
                proof::dto::PresentationDefinitionRequestedCredentialResponseRestDTO,
                proof::dto::PresentationDefinitionFieldRestDTO,
                proof::dto::PresentationDefinitionRuleRestDTO,
                proof::dto::PresentationDefinitionRuleTypeRestEnum,

                proof_schema::dto::CreateProofSchemaRequestRestDTO,
                proof_schema::dto::ClaimProofSchemaRequestRestDTO,
                proof_schema::dto::SortableProofSchemaColumnRestEnum,
                proof_schema::dto::GetProofSchemaListItemResponseRestDTO,
                proof_schema::dto::GetProofSchemaResponseRestDTO,
                proof_schema::dto::ProofClaimSchemaResponseRestDTO,
                proof_schema::dto::ProofInputSchemaRequestRestDTO,
                proof_schema::dto::ProofInputSchemaResponseRestDTO,
                proof_schema::dto::ProofSchemaShareResponseRestDTO,
                proof_schema::dto::ImportProofSchemaRequestRestDTO,
                proof_schema::dto::ImportProofSchemaRestDTO,
                proof_schema::dto::ImportProofSchemaInputSchemaRestDTO,
                proof_schema::dto::ImportProofSchemaClaimSchemaRestDTO,
                proof_schema::dto::ImportProofSchemaCredentialSchemaRestDTO,

                ssi::dto::ConnectIssuerResponseRestDTO,
                ssi::dto::ConnectVerifierResponseRestDTO,
                ssi::dto::ProofRequestClaimRestDTO,
                ssi::dto::IssuerResponseRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataResponseRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataCredentialSchemaRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO,
                ssi::dto::OpenID4VCICredentialDefinitionRequestRestDTO,
                ssi::dto::OpenID4VCICredentialRequestRestDTO,
                ssi::dto::OpenID4VCIProofRequestRestDTO,
                ssi::dto::OpenID4VCICredentialResponseRestDTO,
                ssi::dto::OpenID4VCIDiscoveryResponseRestDTO,
                ssi::dto::OpenID4VCITokenResponseRestDTO,
                ssi::dto::OpenID4VCIErrorResponseRestDTO,
                ssi::dto::OpenID4VCIErrorRestEnum,
                ssi::dto::OpenID4VCITokenRequestRestDTO,
                ssi::dto::OpenID4VCICredentialOfferRestDTO,
                ssi::dto::OpenID4VCIGrantsRestDTO,
                ssi::dto::OpenID4VCIGrantRestDTO,
                ssi::dto::OpenID4VCICredentialOfferCredentialRestDTO,
                ssi::dto::OpenID4VCICredentialOfferClaimDTO,
                ssi::dto::OpenID4VCICredentialOfferClaimValueDTO,
                ssi::dto::OpenID4VCICredentialDefinitionRestDTO,
                ssi::dto::OpenID4VCICredentialSubjectRestDTO,
                ssi::dto::OpenID4VCICredentialValueDetailsRestDTO,
                ssi::dto::OpenID4VPDirectPostRequestRestDTO,
                ssi::dto::InternalPresentationSubmissionMappingRestDTO,
                ssi::dto::OpenID4VPDirectPostResponseRestDTO,
                ssi::dto::OpenID4VPPresentationDefinitionResponseRestDTO,
                ssi::dto::OpenID4VPPresentationDefinitionInputDescriptorRestDTO,
                ssi::dto::OpenID4VPPresentationDefinitionInputDescriptorFormatRestDTO,
                ssi::dto::OpenID4VPPresentationDefinitionConstraintRestDTO,
                ssi::dto::OpenID4VPPresentationDefinitionConstraintFieldRestDTO,
                ssi::dto::OpenID4VPPresentationDefinitionConstraintFieldFilterRestDTO,
                ssi::dto::NestedPresentationSubmissionDescriptorRestDTO,
                ssi::dto::PresentationSubmissionMappingRestDTO,
                ssi::dto::PresentationSubmissionDescriptorRestDTO,
                ssi::dto::TimestampRest,
                ssi::dto::JsonLDContextResponseRestDTO,
                ssi::dto::JsonLDContextRestDTO,
                ssi::dto::JsonLDEntityRestDTO,
                ssi::dto::JsonLDInlineEntityRestDTO,
                ssi::dto::OpenID4VPFormatRestDTO,
                ssi::dto::OpenID4VPClientMetadataResponseRestDTO,
                ssi::dto::OpenID4VPClientMetadataJwkRestDTO,
                ssi::dto::OID4VPAuthorizationEncryptedResponseAlgorithm,
                ssi::dto::OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm,
                ssi::dto::DidDocumentRestDTO,
                ssi::dto::DidVerificationMethodRestDTO,
                ssi::dto::PublicKeyJwkRestDTO,
                ssi::dto::PublicKeyJwkEllipticDataRestDTO,
                ssi::dto::PublicKeyJwkRsaDataRestDTO,
                ssi::dto::PublicKeyJwkOctDataRestDTO,
                ssi::dto::JsonLDNestedEntityRestDTO,
                ssi::dto::JsonLDNestedContextRestDTO,
                ssi::dto::PublicKeyJwkMlweDataRestDTO,
                ssi::dto::GetTrustAnchorResponseRestDTO,
                ssi::dto::GetTrustEntityResponseRestDTO,

                interaction::dto::HandleInvitationRequestRestDTO,
                interaction::dto::HandleInvitationResponseRestDTO,
                interaction::dto::IssuanceAcceptRequestRestDTO,
                interaction::dto::IssuanceRejectRequestRestDTO,
                interaction::dto::PresentationRejectRequestRestDTO,
                interaction::dto::PresentationSubmitRequestRestDTO,
                interaction::dto::PresentationSubmitCredentialRequestRestDTO,
                interaction::dto::ProposeProofRequestRestDTO,
                interaction::dto::ProposeProofResponseRestDTO,

                task::dto::TaskRequestRestDTO,
                task::dto::TaskResponseRestDTO,

                trust_anchor::dto::CreateTrustAnchorRequestRestDTO,
                trust_anchor::dto::TrustAnchorRoleRest,
                trust_anchor::dto::GetTrustAnchorResponseRestDTO,
                trust_anchor::dto::ListTrustAnchorsResponseItemRestDTO,
                trust_anchor::dto::GetTrustAnchorDetailResponseRestDTO,

                trust_entity::dto::CreateTrustEntityRequestRestDTO,
                trust_entity::dto::TrustEntityRoleRest,
                trust_entity::dto::GetTrustEntityResponseRestDTO,
                trust_entity::dto::ListTrustEntitiesResponseItemRestDTO,

                jsonld::dto::ResolveJsonLDContextResponseRestDTO,

                dto::common::GetDidsResponseRestDTO,
                dto::common::GetProofSchemaListResponseRestDTO,

                dto::common::GetCredentialsResponseDTO,
                dto::common::GetCredentialSchemasResponseDTO,
                dto::common::GetProofsResponseRestDTO,
                dto::common::GetKeyListResponseRestDTO,

                dto::common::EntityResponseRestDTO,
                dto::common::EntityShareResponseRestDTO,
                dto::common::SortDirection,

                dto::error::ErrorResponseRestDTO,
                dto::error::ErrorCode,
                dto::error::Cause,

                shared_types::ClaimId,
                shared_types::ClaimSchemaId,
                shared_types::CredentialId,
                shared_types::CredentialSchemaId,
                shared_types::DidId,
                shared_types::DidValue,
                shared_types::EntityId,
                shared_types::HistoryId,
                shared_types::KeyId,
                shared_types::OrganisationId,
                shared_types::ProofSchemaId,
                shared_types::ProofId,
                shared_types::TrustAnchorId,
                shared_types::TrustEntityId,
            )
        ),
        tags(
            (name = "other", description = "Other utility endpoints"),
            (name = "credential_management", description = "Credential management"),
            (name = "credential_schema_management", description = "Credential schema management"),
            (name = "did_management", description = "Did management"),
            (name = "did_resolver", description = "Did resolution"),
            (name = "history_management", description = "History management"),
            (name = "interaction", description = "Holder functionality"),
            (name = "key", description = "Key management"),
            (name = "organisation_management", description = "Organisation management"),
            (name = "proof_management", description = "Proof management"),
            (name = "proof_schema_management", description = "Proof schema management"),
            (name = "ssi", description = "SSI"),
            (name = "task", description = "Background tasks"),
            (name = "trust_anchor", description = "Trust anchors"),
            (name = "trust_entity", description = "Trust entities"),
            (name = "jsonld", description = "JSON-LD"),
        ),
        modifiers(&SecurityAddon)
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components = openapi.components.as_mut().expect("OpenAPI Components");
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("BFF access token"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "OpenID4VCI",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("OpenID4VCI token"))
                        .build(),
                ),
            );
        }
    }

    let mut docs = ApiDoc::openapi();
    docs.info.version = app_version();

    docs
}

fn app_version() -> String {
    build_info::APP_VERSION
        .map(Into::into)
        .unwrap_or_else(|| format!("{}-{}", build_info::PKG_VERSION, build_info::SHORT_COMMIT))
}

fn handle_panic(err: Box<dyn Any + Send + 'static>) -> Response<Body> {
    let message = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic message".to_string()
    };

    tracing::error!("PANIC occurred in request: {message}");

    ErrorResponse::for_panic(message).into_response()
}

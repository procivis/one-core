use utoipa::openapi::extensions::Extensions;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{Contact, ExternalDocs, Server, Tag};
use utoipa::{Modify, OpenApi};

use crate::dto;
use crate::endpoint::{
    config, credential, credential_schema, did, did_resolver, history, interaction, jsonld, key,
    misc, organisation, proof, proof_schema, ssi, task, trust_anchor, trust_entity,
};

pub fn gen_openapi_documentation() -> utoipa::openapi::OpenApi {
    #[derive(OpenApi)]
    #[openapi(
        paths(
            config::controller::get_config,

            organisation::controller::get_organisations,
            organisation::controller::get_organisation,
            organisation::controller::post_organisation,

            key::controller::get_key_list,
            key::controller::get_key,
            key::controller::post_key,
            key::controller::generate_csr,
            key::controller::check_certificate,

            did::controller::get_did_list,
            did::controller::get_did,
            did::controller::post_did,
            did::controller::update_did,
            did::controller::get_did_trust_entity,
            did_resolver::controller::resolve_did,

            credential_schema::controller::get_credential_schema_list,
            credential_schema::controller::import_credential_schema,
            credential_schema::controller::get_credential_schema,
            credential_schema::controller::delete_credential_schema,
            credential_schema::controller::post_credential_schema,
            credential_schema::controller::share_credential_schema,

            credential::controller::get_credential_list,
            credential::controller::share_credential,
            credential::controller::revocation_check,
            credential::controller::suspend_credential,
            credential::controller::reactivate_credential,
            credential::controller::revoke_credential,
            credential::controller::get_credential,
            credential::controller::post_credential,
            credential::controller::delete_credential,

            proof_schema::controller::get_proof_schemas,
            proof_schema::controller::import_proof_schema,
            proof_schema::controller::get_proof_schema_detail,
            proof_schema::controller::post_proof_schema,
            proof_schema::controller::delete_proof_schema,
            proof_schema::controller::share_proof_schema,

            proof::controller::get_proofs,
            proof::controller::share_proof,
            proof::controller::retract_proof,
            proof::controller::get_proof_details,
            proof::controller::post_proof,
            proof::controller::delete_proof_claims,
            proof::controller::get_proof_presentation_definition,

            interaction::controller::handle_invitation,
            interaction::controller::issuance_accept,
            interaction::controller::issuance_reject,
            interaction::controller::presentation_reject,
            interaction::controller::presentation_submit,
            interaction::controller::propose_proof,

            history::controller::get_history_list,
            history::controller::get_history_entry,

            trust_anchor::controller::get_trust_anchors,
            trust_anchor::controller::get_trust_anchor,
            trust_anchor::controller::create_trust_anchor,
            trust_anchor::controller::delete_trust_anchor,

            trust_entity::controller::get_trust_entities,
            trust_entity::controller::get_trust_entity_details,
            trust_entity::controller::create_trust_entity,
            trust_entity::controller::create_remote_trust_entity,
            trust_entity::controller::update_trust_entity,

            jsonld::controller::resolve_jsonld_context,

            task::controller::post_task,

            ssi::controller::get_lvvc_by_credential_id,
            ssi::controller::get_revocation_list_by_id,
            ssi::controller::get_did_web_document,
            ssi::controller::oidc_issuer_get_issuer_metadata,
            ssi::controller::oidc_issuer_service_discovery,
            ssi::controller::oidc_issuer_get_credential_offer,
            ssi::controller::oidc_issuer_create_token,
            ssi::controller::oidc_issuer_create_credential,
            ssi::controller::oidc_verifier_direct_post,
            ssi::controller::oidc_verifier_presentation_definition,
            ssi::controller::oidc_verifier_client_metadata,
            ssi::controller::oidc_verifier_client_request,
            ssi::controller::oidc_verifier_request_data,
            ssi::controller::get_json_ld_context,
            ssi::controller::ssi_get_credential_schema,
            ssi::controller::ssi_get_proof_schema,
            ssi::controller::ssi_get_trust_list,
            ssi::controller::ssi_get_sd_jwt_vc_type_metadata,
            ssi::controller::ssi_get_trust_entity,
            ssi::controller::ssi_post_trust_entity,
            ssi::controller::ssi_patch_trust_entity,

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
                credential::dto::MdocMsoValidityResponseRestDTO,

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

                ssi::dto::LVVCIssuerResponseRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataResponseRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataCredentialSchemaRestDTO,
                ssi::dto::OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO,
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
                ssi::dto::OpenID4VCICredentialDefinitionRestDTO,
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
                ssi::dto::ProcivisSubjectClaimValueRestDTO,
                ssi::dto::SdJwtVcTypeMetadataResponseRestDTO,
                ssi::dto::SdJwtVcDisplayMetadataRestDTO,
                ssi::dto::SdJwtVcRenderingRestDTO,
                ssi::dto::SdJwtVcSimpleRenderingRestDTO,
                ssi::dto::SdJwtVcSimpleRenderingLogoRestDTO,
                ssi::dto::SdJwtVcClaimRestDTO,
                ssi::dto::SdJwtVcClaimSdRestEnum,
                ssi::dto::SdJwtVcClaimDisplayRestDTO,

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
                trust_anchor::dto::GetTrustAnchorResponseRestDTO,
                trust_anchor::dto::ListTrustAnchorsResponseItemRestDTO,
                trust_anchor::dto::GetTrustAnchorDetailResponseRestDTO,

                trust_entity::dto::CreateTrustEntityRequestRestDTO,
                trust_entity::dto::TrustEntityRoleRest,
                trust_entity::dto::GetTrustEntityResponseRestDTO,
                trust_entity::dto::ListTrustEntitiesResponseItemRestDTO,
                trust_entity::dto::CreateRemoteTrustEntityRequestRestDTO,

                jsonld::dto::ResolveJsonLDContextResponseRestDTO,

                dto::common::EntityResponseRestDTO,
                dto::common::EntityShareResponseRestDTO,
                dto::common::SortDirection,

                dto::error::ErrorResponseRestDTO,
                dto::error::ErrorCode,
                dto::error::Cause,

                shared_types::EntityId,
            )
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
                        .description(Some("Local management access token"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "openID4VCI",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("OpenID4VCI token"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "remote-agent",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "LVVC holder or remote Trust-entity owner access token",
                        ))
                        .build(),
                ),
            );
        }
    }

    let mut docs = ApiDoc::openapi();
    docs.info.title = "Procivis One Core API".into();
    docs.info.description = Some(indoc::formatdoc! {"
            The Procivis One Core API enables the full lifecycle of credentials.
            Download the [specification](/APIspec/core.yaml).
        "});
    docs.info.version = "1.0.0".into();
    docs.info.contact = Some(
        Contact::builder()
            .name(Some("Procivis One Docs"))
            .url(Some("https://www.procivis.ch/en/procivis-one#signup"))
            .build(),
    );
    docs.servers = Some(vec![
        Server::builder().url("/").build(),
        Server::builder()
            .url("https://www.procivis-one.com")
            .description(Some("Generated server url"))
            .build(),
    ]);
    docs.tags = Some(get_tags());
    docs.external_docs = Some(
        ExternalDocs::builder()
            .url("https://docs.procivis.ch/")
            .description(Some("See the documentation"))
            .build(),
    );
    if let Some(l) = &mut docs.info.license {
        l.url = Some("https://github.com/procivis/one-core/blob/main/LICENSE".into())
    };

    docs
}

fn get_tags() -> Vec<Tag> {
    vec![
        Tag::builder()
            .name("other")
            .description(Some(indoc::formatdoc! {"
                Returns the system configuration, along with other system information.
                See the [Configuration](/api/configuration) guide for more
                information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "System information")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("organisation_management")
            .description(Some(indoc::formatdoc! {"
                Create organizations. See the
                [Organization](/api/organizations) guide for more
                information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Organizations")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("key")
            .description(Some(indoc::formatdoc! {"
                Create keys and retrieve information on keys created within the current organization.
                Keys are required to create DIDs and issue credentials.
                See the [Keys](/api/resources/keys) guide for more information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Keys")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("did_management")
            .description(Some(indoc::formatdoc! {"
                Create DIDs, deactivate DIDs, and retrieve information on DIDs within the current organization.
                A DID is required to issue credentials, request a proof, and verify credentials.
                See the [DIDs](/api/resources/dids) guide for more information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "DIDs")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("credential_schema_management")
            .description(Some(indoc::formatdoc! {"
                Create, retrieve, and delete credential schemas.
                See the [Credential schemas](/api/resources/credential_schemas) guide
                for more information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Credential schemas")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("credential_management")
            .description(Some(indoc::formatdoc! {"
                Issue, revoke, and retrieve credentials. See the
                [Credentials](/api/resources/credentials) guide for more
                information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Credentials")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("proof_schema_management")
            .description(Some(indoc::formatdoc! {"
                Create, delete, and retrieve proof schemas.
                See the [Proof schemas](/api/resources/proof_schemas) guide for more
                information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Proof schemas")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("proof_management")
            .description(Some(indoc::formatdoc! {"
                Request proofs and retrieve proof requests.
                See the [Proof requests](/api/resources/proof_requests) guide for
                more information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Proof requests")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("interaction")
            .description(Some(indoc::formatdoc! {"
                For wallet agents, handle interactions with issuers and verifiers.
                See the [Wallet interaction](/api/resources/wallet_interaction) guide for more
                information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Wallet interaction")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("history_management")
            .description(Some(indoc::formatdoc! {"
                Retrieve event history. See the
                [History](/api/resources/history) guide for more
                information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "History")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("trust_anchor")
            .description(Some(indoc::formatdoc! {"
                Publish new trust anchors and subscribe to existing trust anchors.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Trust anchors")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("trust_entity")
            .description(Some(indoc::formatdoc! {"
                Add and remove trust entities to and from trust anchors.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Trust entities")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("jsonld")
            .description(Some(indoc::formatdoc! {"
                Operations for credentials formatted with JSON-LD.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "JSON-LD")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("task")
            .description(Some(indoc::formatdoc! {"
                Run tasks.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "Task")
                    .build(),
            ))
            .build(),
        Tag::builder()
            .name("ssi")
            .description(Some(indoc::formatdoc! {"

                :::warning

                These endpoints handle low-level mechanisms in interactions between agents.
                Deep understanding of the involved protocols is recommended.

                :::

            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "(Advanced) SSI")
                    .build(),
            ))
            .build(),
    ]
}

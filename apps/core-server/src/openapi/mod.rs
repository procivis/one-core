use std::sync::Arc;

use one_core::config::core_config::CoreConfig;
use proc_macros::modify_schema_autodetect;
use url::Url;
use utoipa::openapi::extensions::Extensions;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{Contact, ExternalDocs, Object, Server, Tag};
use utoipa::{Modify, OpenApi};

pub(crate) mod permissions;
pub(crate) mod swagger_plugin;

use crate::build_info::{APP_VERSION, build};
use crate::openapi::permissions::PermissionsModifier;
use crate::{AuthMode, ServerConfig};

/// Schemas that no request or response body reaches. `test_openapi_schema_regressions` fails on
/// a dangling `$ref`.
pub(crate) fn base_openapi() -> utoipa::openapi::OpenApi {
    #[derive(OpenApi)]
    #[openapi(components(schemas(
        shared_types::EntityId,
        shared_types::RevocationListId,
        crate::dto::common::Boolean,
        crate::dto::common::SortDirection,
        crate::dto::error::ErrorResponseRestDTO,
        crate::endpoint::credential::dto::CredentialListItemResponseRestDTO,
        crate::endpoint::history::dto::HistoryResponseRestDTO,
        crate::endpoint::identifier::dto::CertificateRolesMatchModeRestEnum,
        crate::endpoint::organisation::dto::OrganisationListItemResponseRestDTO,
        crate::endpoint::proof::dto::ProofListItemResponseRestDTO,
        crate::endpoint::statistics::dto::IssuerSchemaStatsResponseRestDTO,
        crate::endpoint::statistics::dto::SystemInteractionStatsResponseRestDTO,
        crate::endpoint::statistics::dto::SystemManagementStatsResponseRestDTO,
        crate::endpoint::statistics::dto::VerifierSchemaStatsResponseRestDTO,
        crate::endpoint::trust_collection::dto::TrustListSubscriptionListItemResponseRestDTO,
        crate::endpoint::trust_list_publication::dto::TrustEntryListItemResponseRestDTO,
        crate::endpoint::trust_list_publication::dto::TrustListPublicationListItemResponseRestDTO,
    )))]
    struct ApiDoc;

    ApiDoc::openapi()
}

pub(crate) fn gen_openapi_documentation(
    mut docs: utoipa::openapi::OpenApi,
    server_config: Arc<ServerConfig>,
    core_config: Arc<CoreConfig>,
) -> utoipa::openapi::OpenApi {
    struct SecurityAddon {
        config: Arc<ServerConfig>,
    }

    impl Modify for SecurityAddon {
        #[expect(clippy::expect_used)]
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components = openapi.components.as_mut().expect("OpenAPI Components");
            match self.config.auth {
                AuthMode::UnsafeNone => {}
                AuthMode::UnsafeStatic { .. } | AuthMode::SecurityTokenService { .. } => {
                    components.add_security_scheme(
                        "bearer",
                        SecurityScheme::Http(
                            HttpBuilder::new()
                                .scheme(HttpAuthScheme::Bearer)
                                .description(Some("Local management access token"))
                                .build(),
                        ),
                    );
                }
            }
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
                        .description(Some("Remote Trust-entity owner access token"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "wallet-unit",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Wallet unit proof of authentication key possession."))
                        .build(),
                ),
            );
        }
    }

    let security_addon = SecurityAddon {
        config: server_config.clone(),
    };
    security_addon.modify(&mut docs);

    PermissionsModifier.modify(&mut docs);

    CoreConfigModifier::new(core_config).modify(&mut docs);

    docs.info.title = "Procivis One Core API".into();
    docs.info.description = Some(indoc::formatdoc! {"
            The Procivis One Core API enables the full lifecycle of credentials.
        "});
    docs.info.version = APP_VERSION
        .unwrap_or(&format!(
            "UNTAGGED: {}, {}",
            build::SHORT_COMMIT,
            build::COMMIT_DATE_3339
        ))
        .to_string();
    docs.info.contact = Some(
        Contact::builder()
            .name(Some("Procivis One Docs"))
            .url(Some("https://www.procivis.ch/en/procivis-one#signup"))
            .build(),
    );
    docs.servers = Some(vec![{
        let mut url = "".to_string();
        if let Ok(base_url) = Url::try_from(server_config.core_base_url.as_str()) {
            match base_url.path() {
                "/" => {}
                path => {
                    url = path.to_string();
                }
            }
        }

        Server::builder()
            .url(url)
            .description(Some("Local server url"))
            .build()
    }]);
    docs.tags = Some(get_tags(server_config));
    docs.external_docs = Some(
        ExternalDocs::builder()
            .url("https://docs.procivis.ch/")
            .description(Some("See the documentation"))
            .build(),
    );
    if let Some(l) = &mut docs.info.license {
        l.url = Some("https://github.com/procivis/one-core/blob/main/LICENSE".into());
        l.identifier = None;
    };

    docs
}

fn get_tags(config: Arc<ServerConfig>) -> Vec<Tag> {
    let mut tags = vec![create_tag(
        "other",
        "System Information",
        indoc::indoc! {"System information and configuration. Use these endpoints to inspect
        your deployment's available components - credential formats, protocols,
        key algorithms, and many more - and to retrieve other system-level
        information."},
    )];

    if config.enable_management_endpoints {
        tags.extend(vec![
            create_tag("organisation_management", "Organizations",
                indoc::indoc! {"The organization is the fundamental unit in Procivis One.
                All issuing, holding, and verifying actions are performed by an
                organization. Keys, DIDs, credentials, and proofs belong exclusively
                to the organization that created them."}
            ),
            create_tag("key", "Keys",
                indoc::indoc! {"Manage cryptographic keys. Keys are the foundation of identifiers — used to
                create DIDs, certificates, and CAs, or as identifiers directly. Private keys
                are stored securely and never exposed through the API.

                Related guide: [Keys](https://docs.procivis.ch/keys)"}
            ),
            create_tag("identifier_management", "Identifiers",
                indoc::indoc! {"Create and manage identifiers of different types for different identity
                ecosystems. An identifier is needed to issue, hold, or verify."}
            ),
            create_tag("certificate_management", "Certificates",
                indoc::indoc! {"Manage certificates in the system. To add a certificate as an identifier,
                see the Identifiers endpoints."}
            ),
            create_tag("did_management", "DIDs",
                indoc::indoc! {"Use the identifier API to create DIDs. The system assigns an ID to both
                the identifier and the DID. Use the DID ID returned from the identifier
                response with this DID API for management operations like deactivation."}
            ),
            create_tag("credential_schema_management", "Credential Schemas",
                indoc::indoc! {"A credential schema defines the structure and format of a credential,
                including the attributes that issuers make claims about. Schemas also
                specify how issued credentials should be presented in digital wallets,
                whether revocation methods are used, and issuer preferences for wallet
                storage type.

                The system supports the creation of as many credential schemas as needed."}
            ),
            create_tag("credential_management", "Credentials",
                indoc::indoc! {"Issue credentials and manage the lifecycle of issued credentials, including
                suspension, reactivation, revocation and status check for holders and verifiers.

                Create a credential by specifying a schema and making claims about a subject.
                Then create a share endpoint URL for the wallet holder to access the offered
                credential. Suspension and revocation options are determined by the schema."}
            ),
            create_tag("proof_schema_management", "Proof Schemas",
                indoc::indoc! {"Manage proof schemas, which define the claims requested from a holder during
                verification. A proof schema can combine claims from any number of credential
                schemas in your organization.

                Related guide: [Proof schemas](https://docs.procivis.ch/proof-schemas)"}
            ),
            create_tag("proof_management", "Proof Requests",
                indoc::indoc! {"A proof request is a request of one or more claims from a wallet holder.

                Create a proof request then create a share endpoint URL for the holder
                to access the request. Any proof shared is verified.

                This resource also includes claim data deletion and presentation definition,
                a filtering function for wallet holders to see what credentials stored in
                their wallet match a proof request.

                Related guide: [Verify](https://docs.procivis.ch/verify)"}
            ),
            create_tag("interaction", "Wallet Interaction",
                indoc::indoc! {"For wallet agents, handle interactions with issuers and verifiers.

                When the holder scans the QR code offered by an issuer or a verifier, the
                handle invitation endpoint takes the encoded url and returns the interaction
                ID along with either the credential being offered or the proof being requested.

                The holder then makes the choice to accept or reject the exchange.

                Related guide: [Wallets](https://docs.procivis.ch/hold)"}
            ),
            create_tag("history_management", "History",
                indoc::indoc! {"Manage and query the event history log. External services use this API
                to submit history entries to Core's centralized history service; all
                consumers use it to list or retrieve recorded events."}
            ),
            create_tag("managed_instance", "Managed instances (Provider)",
                "For Wallet and Verifier Providers, manage the lifecycle of registered instances."
            ),
            create_tag("instance", "Instances (Holder)",
                "For wallet and verifier instances, register with the provider and check status."
            ),
            create_tag("signature", "Signatures", "Create and revoke signatures."),
            create_tag("qes", "Qualified Electronic Signature (QES)", "Document signing."),
            create_tag("jsonld", "JSON-LD", "Retrieve cached JSON-LD context documents."),
            create_tag("task", "Tasks",
                indoc::indoc! {"Trigger configured maintenance and operational tasks.
                Tasks can also be run from the CLI or scheduled as cron
                jobs. See [Regular Tasks](https://docs.procivis.ch/reference/configuration/core#regular-tasks)
                for supported task types and their parameters."}
            ),
            create_tag("cache", "Cache",
                indoc::indoc! {"Manage the remote entity cache. See [Caching](https://docs.procivis.ch/configure/caching)
                for configuration."}
            ),
            create_tag("trust_list_publication_management", "Trust List Publications", "Publish and manage trust lists."),
            create_tag("trust_collection_management", "Trust List Collections", "Manage collections of trust list subscriptions."),
            create_tag("statistics", "Statistics",
                indoc::indoc! {"Retrieve organizational and system statistics including issuance and
                verification counts, and active wallet unit counts."}
            ),
        ]);
    }
    if config.enable_external_endpoints {
        let warning_description = indoc::indoc! {"
            :::warning

            These endpoints handle low-level mechanisms in interactions between agents.
            Deep understanding of the involved protocols is recommended.

            :::
        "};
        tags.extend(vec![
            create_tag("ssi", "(Advanced) SSI", warning_description),
            create_tag(
                "openid4vci-final1_0",
                "(Advanced) OID4VCI Final 1.0",
                warning_description,
            ),
            create_tag(
                "openid4vp-final-1.0",
                "(Advanced) OID4VP Final 1.0",
                warning_description,
            ),
            create_tag(
                "openid4vci-final1_0-swiyu",
                "(Advanced) OID4VCI Final 1.0 - swiyu",
                warning_description,
            ),
            create_tag(
                "openid4vp-final-1.0-swiyu",
                "(Advanced) OID4VP Final 1.0 - swiyu",
                warning_description,
            ),
        ]);
    }
    tags
}

fn create_tag(tag_name: &str, display_name: &str, description: &str) -> Tag {
    Tag::builder()
        .name(tag_name)
        .description(Some(description))
        .extensions(Some(
            Extensions::builder()
                .add("x-displayName", display_name)
                .build(),
        ))
        .build()
}

pub trait CoreConfigModifySchema {
    fn core_config_modify_schema(core_config: &CoreConfig, object: &mut Object);
}

#[modify_schema_autodetect(path = "apps/core-server/src")]
struct CoreConfigModifier {
    core_config: Arc<CoreConfig>,
}

impl CoreConfigModifier {
    fn new(core_config: Arc<CoreConfig>) -> Self {
        Self { core_config }
    }
}

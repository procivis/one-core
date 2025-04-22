use std::sync::Arc;

use utoipa::openapi::extensions::Extensions;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{Contact, ExternalDocs, Server, Tag};
use utoipa::{Modify, OpenApi};
use utoipauto::utoipauto;

use crate::build_info::{build, APP_VERSION};
use crate::ServerConfig;

pub(crate) fn gen_openapi_documentation(config: Arc<ServerConfig>) -> utoipa::openapi::OpenApi {
    #[utoipauto(paths = "./apps/core-server/src")]
    #[derive(OpenApi)]
    #[openapi(
        components(schemas(shared_types::EntityId)),
        modifiers(&SecurityAddon),
    )]
    struct ApiDoc;

    struct ApiDocModifier {
        config: Arc<ServerConfig>,
    }

    struct SecurityAddon;

    impl Modify for ApiDocModifier {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if !self.config.enable_management_endpoints || !self.config.enable_external_endpoints {
                openapi.paths.paths.retain(|path, _| {
                    if path.starts_with("/ssi") {
                        return self.config.enable_external_endpoints;
                    }

                    if path.starts_with("/api") {
                        return self.config.enable_management_endpoints;
                    }

                    true
                });
            }
        }
    }

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
    let modifier = ApiDocModifier {
        config: config.clone(),
    };
    modifier.modify(&mut docs);
    docs.info.title = "Procivis One Core API".into();
    docs.info.description = Some(indoc::formatdoc! {"
            The Procivis One Core API enables the full lifecycle of credentials.
            Download the [specification](../APIspec/core.yaml).
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
    docs.servers = Some(vec![
        Server::builder()
            .url("")
            .description(Some("Local server url"))
            .build(),
        Server::builder()
            .url("https://www.procivis-one.com")
            .description(Some("Generated server url"))
            .build(),
    ]);
    docs.tags = Some(get_tags(config));
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
    let mut tags = vec![Tag::builder()
        .name("other")
        .description(Some(indoc::formatdoc! {"
                Returns the system configuration, along with other system information.

                Related guide: [Configuration](/configure)
            "}))
        .extensions(Some(
            Extensions::builder()
                .add("x-displayName", "System information")
                .build(),
        ))
        .build()];

    if config.enable_management_endpoints {
        tags.append(& mut vec![Tag::builder()
                       .name("organisation_management")
                       .description(Some(indoc::formatdoc! {"
                The **Organization** is the fundamental unit of _Procivis One_. All actions
                related to issuing, holding and verifying are taken _by_ an organization. This
                means that keys, DIDs, credentials and proofs belong to the organization used
                to create them and to no other.

                Related guide: [Organizations](/organizations)
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
                Create cryptographic keys using different key algorithms and storage types.
                The public key can be seen in the system (`publicKey`) and is used to verify
                credentials. The private key is stored in the system and used to sign credentials,
                but cannot be exported and is not visible through the API.

                At least one key pair is needed to create a DID, and a DID is required to issue,
                hold, or verify credentials.

                This resource also generates Certificate Signing Requests, a necessary component
                of ISO mdoc issuance and verification.

                Related guide: [Keys](/keys)
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
                Create and manage DIDs (Decentralized Identifiers), a type of globally unique
                identifier for an entity. The DID is a URI that can be resolved to
                a DID document which offers metadata about the identified entity.

                Because a DID is created in association with a public/private key pair, the
                controller of the private key is able to prove control of the DID and thus
                authenticate themselves.

                A DID is needed to issue credentials, request a proof, and verify credentials.

                Related guide: [DIDs](/dids)
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
                A credential schema defines the structure and format of a credential, including
                the attributes about which issuers make claims. Schemas carry information about
                issued credentials such as how an issued credential should be presented in a
                digital wallet, whether it was issued with a revocation method and issuer
                preferences for wallet storage type.

                The system supports the creation of as many credential schemas as is needed.

                Related guide: [Credential schemas](/credential-schemas)
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
                Issue credentials and manage the lifecycle of issued credentials, including
                suspension, reactivation, revocation and status check for holders and verifiers.

                Create a credential by specifying a schema and making claims about a subject.
                Then create a share endpoint URL for the wallet holder to access the offered
                credential. Suspension and revocation options are determined by the schema.

                Related guide: [Issuance](/issue)
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
                A proof schema defines the attributes a verifier requests from a credentials holder.
                It is the collection of items of information to be requested.

                Proof schemas are built from attributes defined in credential schemas. Each item of
                information to be requested must first be part of a credential schema in the system.
                Proof schemas are not restricted to pulling attributes from a single credential schema
                or from credential schemas using a particular credential format; a single proof schema
                can be composed of any number of attributes from any number of credential schemas within
                the organization.

                Proof schemas cannot combine hardware- and software-based credentials.

                Related guide: [Proof schemas](/proof-schemas)
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
                A proof request is a request of one or more claims from a wallet holder.

                Create a proof request then create a share endpoint URL for the holder
                to access the request. Any proof shared is verified.

                This resource also includes claim data deletion and presentation definition,
                a filtering function for wallet holders to see what credentials stored in
                their wallet match a proof request.

                Related guide: [Verify](/verify)
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

                When the holder scans the QR code offered by an issuer or a verifier, the
                handle invitation endpoint takes the encoded url and returns the interaction
                ID along with either the credential being offered or the proof being requested.

                The holder then makes the choice to accept or reject the exchange.

                Related guide: [Wallet interaction](/hold/wallet-interaction)
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
                Retrieve event history.

                Related guide: [History](/history)
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
                Manage trust anchors as a publisher or subscribe to trust anchors as a consumer.

                Related guide: [Trust](/trust)
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
                Manage trust entities on an anchor.

                Related guide: [Trust](/trust)
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

                Related guide: [Configuration](/configure)
            "}))
                       .extensions(Some(
                           Extensions::builder()
                               .add("x-displayName", "Task")
                               .build(),
                       ))
                       .build(),
                   Tag::builder()
                       .name("cache")
                       .description(Some(indoc::formatdoc! {"
                Manage cached entities.

                Related guide: [Configuration](/configure)
            "}))
                       .extensions(Some(
                           Extensions::builder()
                               .add("x-displayName", "Cache")
                               .build(),
                       ))
                       .build()]);
    }
    if config.enable_external_endpoints {
        tags.append(&mut vec![
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
            Tag::builder()
                .name("openid4vci-draft13")
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
            Tag::builder()
                .name("openid4vp-draft20")
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
            Tag::builder()
                .name("openid4vp-draft25")
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
        ]);
    }
    tags
}

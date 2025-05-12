//! The **Procivis One Core** is a library for issuing, holding and verifying
//! verifiable credentials.
//!
//! Self-sovereign identity (SSI) is a model of digital identity that enables individuals
//! to receive and hold their identity and credentials, controlling when and with whom
//! they share them, without requesting permission from a centralized authority or
//! identity provider.
//!
//! The library provides all SSI functionality needed to issue, hold and
//! verify credentials, including credential formats, exchange protocols, digital
//! signature schemes and associated key handling, DID management and revocation
//! methods. Additionally, implementations of technologies can be used individually
//! for modular functionality.
//!
//! ## Features
//!
//! See the README for a complete list of supported technologies and standards.
//!
//! The **Providers** of the one-core, and one-crypto (delimited in its own directory to
//! enable future certification, e.g. in
//! the [NIST Cryptographic Module Validation Program (CMVP)][cmvp]), are modular
//! implementations of the complete range of functionality. Developers can use providers
//! - or implementations of individual technologies from within a provider - for modular
//!   functionality.
//!
//! **one-dev-services** is a service layer that offers developer APIs for orchestrating the whole
//! suite of providers for simplified workflows in issuing, holding, or verifying. Services
//! return provider implementations.
//!
//! ## Getting started
//!
//! ### Providers
//!
//! See **/examples** in the [repository][repo] for a few iterations of using the provider
//! implementations:
//!
//! - `examples/signature_example`: Issuing, presenting as a holder, and verifying a credential via the credentials service
//! - `examples/signature_example`: Signing and verifying via the signature service
//! - `examples/did_resolution_example`: Resolving DIDs via the DID service or using the
//!   implementations directly
//!
//! ### One dev services
//!
//! Dev services provides developer APIs for simple and easy-to-use functionalities
//! of the library and its supported technologies. As an orchestration
//! layer, it provides the simplest access to related functions with
//! the least amount of effort. Use the provided [services][serv] to get started.
//! Additional services will be added.
//!
//! To get started with the provided services, initialize the core:
//!
//! ```ignore rust
//! /// `None` initializes the Core with the default configuration
//! let core = OneDevCore::new(None).unwrap();
//! ```
//!
//! Then start using the services, e.g.:
//! ```ignore rust
//! let key_pair = core
//!     .signature_service
//!     .get_key_pair(&KeyAlgorithmType::Ecdsa)
//!     .expect("Key pair creation failed");
//! ```
//!
//! ## Documentation
//!
//! This site provides descriptions of crates, modules, and traits for the providers.
//!
//! Additionally, higher-level documentation can be found at the root
//! [Procivis One documentation][docs] site. This includes:
//!
//! - The complete list of **Procivis One** supported technologies
//! - Trial access to the full solution
//! - APIs and SDK documentation
//! - Conceptual topics
//!
//! [cmvp]: https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program
//! [cryp]: ../one_crypto/index.html
//! [cs]: ..//one_core/service/credential_service/struct.CredentialService.html
//! [docs]: https://docs.procivis.ch/
//! [dresolv]: ..//one_core/service/did_service/struct.DidService.html
//! [repo]: https://github.com/procivis/one-core
//! [serv]: ..//one_core/service/index.html
//! [sl]: https://w3c.github.io/vc-bitstring-status-list/
//! [ss]: ..//one_core/service/signature_service/struct.SignatureService.html

#![doc(html_favicon_url = "https://docs.procivis.ch/img/favicon.svg")]

use std::collections::HashMap;
use std::default::Default;
use std::error::Error;
use std::sync::Arc;

use config::OneCoreConfig;
use indexmap::IndexMap;
use model::{CredentialFormat, DidMethodType, StorageType};
use one_core::config::core_config;
use one_core::provider::caching_loader::CachingLoader;
use one_core::provider::credential_formatter::json_ld::context::caching_loader::JsonLdCachingLoader;
use one_core::provider::credential_formatter::json_ld_bbsplus::{
    JsonLdBbsplus, Params as JsonLdParams,
};
use one_core::provider::credential_formatter::jwt_formatter::{JWTFormatter, Params as JWTParams};
use one_core::provider::credential_formatter::provider::CredentialFormatterProviderImpl;
use one_core::provider::credential_formatter::sdjwt_formatter::{
    Params as SDJWTParams, SDJWTFormatter,
};
use one_core::provider::did_method::jwk::JWKDidMethod;
use one_core::provider::did_method::key::KeyDidMethod;
use one_core::provider::did_method::keys::{Keys, MinMax};
use one_core::provider::did_method::provider::DidMethodProviderImpl;
use one_core::provider::did_method::universal::{
    Params as UniversalDidMethodParams, UniversalDidMethod,
};
use one_core::provider::did_method::web::{Params as WebDidMethodParams, WebDidMethod};
use one_core::provider::http_client::HttpClient;
use one_core::provider::http_client::reqwest_client::ReqwestClient;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::bbs::BBS;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::key_storage::KeyStorage;
use one_core::provider::key_storage::internal::{
    InternalKeyProvider, Params as InternalKeyProviderParams,
};
use one_core::provider::key_storage::provider::KeyProviderImpl;
use one_core::provider::remote_entity_storage::RemoteEntityType;
use one_core::provider::remote_entity_storage::in_memory::InMemoryStorage;
use one_crypto::CryptoProviderImpl;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::bbs::BBSSigner;
use one_crypto::signer::crydi3::CRYDI3Signer;
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::signer::eddsa::EDDSASigner;
use one_crypto::utilities::generate_random_bytes;
use secrecy::SecretSlice;
use service::credential_service::CredentialService;
use service::did_service::DidService;
use service::signature_service::SignatureService;

pub mod config;
pub mod model;
pub mod service;

pub struct OneDevCore {
    pub signature_service: SignatureService,
    pub did_service: DidService,
    pub credential_service: CredentialService,
}

impl Default for OneDevCore {
    fn default() -> Self {
        Self::new(None, Arc::new(ReqwestClient::default())).unwrap()
    }
}

impl OneDevCore {
    pub fn new(
        config: Option<OneCoreConfig>,
        client: Arc<dyn HttpClient>,
    ) -> Result<Self, Box<dyn Error>> {
        let config = config.unwrap_or(OneCoreConfig {
            ..Default::default()
        });

        // initialize crypto provider
        let crypto_provider = Arc::new(CryptoProviderImpl::new(
            HashMap::from_iter(vec![("sha-256".to_string(), Arc::new(SHA256 {}) as _)]),
            HashMap::from_iter(vec![
                ("Ed25519".to_string(), Arc::new(EDDSASigner {}) as _),
                ("ECDSA".to_string(), Arc::new(ECDSASigner {}) as _),
                ("CRYDI3".to_string(), Arc::new(CRYDI3Signer {}) as _),
                ("BBS".to_string(), Arc::new(BBSSigner {}) as _),
            ]),
        ));

        // initialize key algorithm provider
        let key_algorithms: HashMap<core_config::KeyAlgorithmType, Arc<dyn KeyAlgorithm>> =
            HashMap::from_iter(vec![
                (core_config::KeyAlgorithmType::Eddsa, Arc::new(Eddsa) as _),
                (core_config::KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa) as _),
                (core_config::KeyAlgorithmType::BbsPlus, Arc::new(BBS) as _),
            ]);
        let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(key_algorithms));

        // initialize key storage provider
        let key_storages: HashMap<String, Arc<dyn KeyStorage>> = HashMap::from_iter(vec![(
            StorageType::Internal.to_string(),
            Arc::new(InternalKeyProvider::new(
                key_algorithm_provider.clone(),
                InternalKeyProviderParams {
                    // use a stable key in production scenarios, this is just good enough for examples
                    encryption: SecretSlice::from(generate_random_bytes::<32>().to_vec()),
                },
            )) as _,
        )]);
        let key_storage_provider = Arc::new(KeyProviderImpl::new(key_storages));

        // initialize did method provider
        let universal_resolver = Arc::new(UniversalDidMethod::new(
            UniversalDidMethodParams {
                resolver_url: config.did_method_config.universal_resolver_url,
                supported_method_names: vec!["ion".to_string()],
            },
            client.clone(),
        ));
        let did_methods = IndexMap::from_iter(vec![
            (
                DidMethodType::Jwk.to_string(),
                Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as _,
            ),
            (
                DidMethodType::Key.to_string(),
                Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())) as _,
            ),
            (
                DidMethodType::Web.to_string(),
                Arc::new(WebDidMethod::new(
                    &None,
                    client.clone(),
                    WebDidMethodParams {
                        resolve_to_insecure_http: Some(false),
                        keys: Keys {
                            global: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            assertion_method: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            authentication: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            capability_delegation: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            capability_invocation: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                            key_agreement: MinMax {
                                min: config.did_method_config.key_count_range.0,
                                max: config.did_method_config.key_count_range.1,
                            },
                        },
                    },
                )?) as _,
            ),
        ]);

        let did_caching_loader = CachingLoader::new(
            RemoteEntityType::DidDocument,
            Arc::new(InMemoryStorage::new(HashMap::new())),
            config.caching_config.did.cache_size,
            config.caching_config.did.cache_refresh_timeout,
            config.caching_config.did.refresh_after,
        );
        let did_method_provider =
            Arc::new(DidMethodProviderImpl::new(did_caching_loader, did_methods));

        // initialize credential formatter provider
        let json_ld_caching_loader = JsonLdCachingLoader::new(
            RemoteEntityType::JsonLdContext,
            Arc::new(InMemoryStorage::new(HashMap::new())),
            config.caching_config.json_ld_context.cache_size,
            config.caching_config.json_ld_context.cache_refresh_timeout,
            config.caching_config.json_ld_context.refresh_after,
        );
        let credential_formatter_provider = Arc::new(CredentialFormatterProviderImpl::new(
            HashMap::from_iter(vec![
                (
                    CredentialFormat::Jwt.to_string(),
                    Arc::new(JWTFormatter::new(
                        JWTParams {
                            leeway: config.formatter_config.leeway,
                            embed_layout_properties: config
                                .formatter_config
                                .embed_layout_properties,
                        },
                        key_algorithm_provider.clone(),
                    )) as _,
                ),
                (
                    CredentialFormat::SdJwt.to_string(),
                    Arc::new(SDJWTFormatter::new(
                        SDJWTParams {
                            leeway: config.formatter_config.leeway,
                            embed_layout_properties: config
                                .formatter_config
                                .embed_layout_properties,
                        },
                        crypto_provider.clone(),
                        did_method_provider.clone(),
                    )) as _,
                ),
                (
                    CredentialFormat::JsonLdBbsPlus.to_string(),
                    Arc::new(JsonLdBbsplus::new(
                        JsonLdParams {
                            leeway: time::Duration::seconds(
                                config.formatter_config.leeway.try_into().unwrap(),
                            ),
                            embed_layout_properties: false,
                            allowed_contexts: None,
                        },
                        crypto_provider.clone(),
                        None,
                        did_method_provider.clone(),
                        key_algorithm_provider.clone(),
                        json_ld_caching_loader,
                        client,
                    )) as _,
                ),
            ]),
        ));

        let signature_service =
            SignatureService::new(crypto_provider, key_algorithm_provider.clone());

        let did_service = DidService::new(did_method_provider.clone(), Some(universal_resolver));

        let credential_service = CredentialService::new(
            key_storage_provider,
            credential_formatter_provider,
            key_algorithm_provider,
            did_method_provider,
        );

        Ok(Self {
            signature_service,
            did_service,
            credential_service,
        })
    }
}

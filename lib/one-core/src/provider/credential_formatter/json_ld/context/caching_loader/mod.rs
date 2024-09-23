use std::string::FromUtf8Error;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use json_ld::{Loader, RemoteDocument};
use json_syntax::Parse;
use locspan::Location;
use rdf_types::IriVocabulary;
use sophia_jsonld::loader::FutureExt;
use time::format_description::well_known::Rfc2822;
use time::macros::offset;
use time::OffsetDateTime;

use crate::provider::caching_loader::{CachingLoader, CachingLoaderError, ResolveResult, Resolver};
use crate::provider::http_client::HttpClient;
use crate::provider::remote_entity_storage::RemoteEntityStorageError;

#[cfg(test)]
mod test;

pub struct JsonLdResolver {
    pub client: Arc<dyn HttpClient>,
}

impl JsonLdResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

pub type JsonLdCachingLoader = CachingLoader<JsonLdResolverError>;

#[async_trait]
impl Resolver for JsonLdResolver {
    type Error = JsonLdResolverError;

    async fn do_resolve(
        &self,
        url: &str,
        last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let mut builder = self.client.get(url);

        if let Some(last_modified) = last_modified {
            builder = builder.header(
                "If-Modified-Since",
                &last_modified
                    .to_offset(offset!(+0))
                    .format(&RFC_2822_BUT_WITH_GMT)
                    .map_err(|e| JsonLdResolverError::TimeError(e.to_string()))?,
            );
        }

        let response = builder
            .send()
            .await
            .map_err(|e| JsonLdResolverError::Reqwest(e.to_string()))?
            .error_for_status()
            .map_err(|e| JsonLdResolverError::Reqwest(e.to_string()))?;
        if response.status.is_success() {
            Ok(ResolveResult::NewValue(response.body))
        } else if response.status.is_redirection() {
            let result = response.header_get("Last-Modified");
            let last_modified = match result {
                None => OffsetDateTime::now_utc(),
                Some(value) => OffsetDateTime::parse(value, &Rfc2822)?,
            };
            Ok(ResolveResult::LastModificationDateUpdate(last_modified))
        } else {
            Err(JsonLdResolverError::UnexpectedStatusCode(
                response.status.to_string(),
            ))
        }
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum JsonLdResolverError {
    #[error("HTTP error: Cannot parse Last-Modified header")]
    CannotParseLastModifiedHeader,
    #[error("HTTP error: received 3xx status code when 2xx was expected")]
    ReceivedStatus3xxInsteadOf2xx,
    #[error("HTTP error: unexpected status code: `{0}`")]
    UnexpectedStatusCode(String),

    #[error("Caching loader error: `{0}`")]
    CachingLoaderError(#[from] CachingLoaderError),
    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("OffsetDateTime parse error: `{0}`")]
    OffsetDateTimeError(#[from] time::error::Parse),
    #[error("Remote entity storage error: `{0}`")]
    RemoteEntityStorageError(#[from] RemoteEntityStorageError),

    #[error("URL parse error: `{0}`")]
    UrlParseError(#[from] url::ParseError),

    /*
     * External errors which don't implement Clone on error types
     * Clone is required for interacting with sophia_jsonld
     */
    #[error("JSON parse error: `{0}`")]
    JsonParseError(String),
    #[error("MIME from str error: `{0}`")]
    MimeFromStrError(String),
    #[error("HTTP error: `{0}`")]
    Reqwest(String),
    #[error("Time error: `{0}`")]
    TimeError(String),
}

type ArcIri = sophia_api::prelude::Iri<Arc<str>>;

#[derive(Clone)]
pub struct ContextCache {
    loader: JsonLdCachingLoader,
    resolver: Arc<JsonLdResolver>,
}

impl ContextCache {
    pub fn new(loader: JsonLdCachingLoader, client: Arc<dyn HttpClient>) -> Self {
        Self {
            loader,
            resolver: Arc::new(JsonLdResolver { client }),
        }
    }
}

impl Loader<ArcIri, Location<ArcIri>> for ContextCache {
    type Output = json_syntax::Value<Location<ArcIri>>;
    type Error = JsonLdResolverError;

    #[inline(always)]
    fn load_with<'a>(
        &'a mut self,
        _namespace: &mut impl IriVocabulary<Iri = ArcIri>,
        url: ArcIri,
    ) -> BoxFuture<
        'a,
        Result<
            RemoteDocument<ArcIri, Location<ArcIri>, json_syntax::Value<Location<ArcIri>>>,
            Self::Error,
        >,
    >
    where
        ArcIri: 'a,
    {
        async move {
            let context = self.loader.get(url.as_str(), self.resolver.clone()).await?;
            let context_str = String::from_utf8(context)?;

            let doc = json_syntax::Value::parse_str(&context_str, |span| {
                Location::new(url.to_owned(), span)
            })
            .map_err(|e| JsonLdResolverError::JsonParseError(e.to_string()))?;

            Ok(RemoteDocument::new(
                Some(url.to_owned()),
                Some(
                    "application/ld+json"
                        .parse()
                        .map_err(|e: mime::FromStrError| {
                            JsonLdResolverError::MimeFromStrError(e.to_string())
                        })?,
                ),
                doc,
            ))
        }
        .boxed()
    }
}

const RFC_2822_BUT_WITH_GMT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

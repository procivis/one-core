use crate::model::json_ld_context::JsonLdContext;
use crate::repository::error::DataLayerError;
use crate::repository::json_ld_context_repository::JsonLdContextRepository;
use futures::future::BoxFuture;
use json_ld::{Loader, RemoteDocument};
use json_syntax::Parse;
use locspan::{Location, Meta};
use rdf_types::IriVocabulary;
use sophia_jsonld::loader::FutureExt;
use std::string::FromUtf8Error;
use std::sync::Arc;
use time::format_description::well_known::Rfc2822;
use time::macros::offset;
use time::OffsetDateTime;
use uuid::Uuid;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct CachingLoader {
    pub cache_size: u32,
    pub cache_refresh_timeout: time::Duration,
    pub client: reqwest::Client,
    pub json_ld_context_repository: Arc<dyn JsonLdContextRepository>,
}

#[derive(Debug, thiserror::Error)]
pub enum CachingLoaderError {
    #[error("HTTP error: Cannot parse Last-Modified header")]
    CannotParseLastModifiedHeader,
    #[error("HTTP error: received 3xx status code when 2xx was expected")]
    ReceivedStatus3xxInsteadOf2xx,
    #[error("HTTP error: received status 304 without Last-Modified header")]
    ReceivedStatus304WithoutLastModifiedHeader,
    #[error("HTTP error: unexpected status code: `{0}`")]
    UnexpectedStatusCode(String),

    #[error("Data layer error: `{0}`")]
    DataLayerError(#[from] DataLayerError),
    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("JSON parse error: `{0}`")]
    JsonParseError(#[from] JsonParseError),
    #[error("MIME from str error: `{0}`")]
    MimeFromStrError(#[from] mime::FromStrError),
    #[error("OffsetDateTime parse error: `{0}`")]
    OffsetDateTimeError(#[from] time::error::Parse),
    #[error("HTTP error: `{0}`")]
    Reqwest(#[from] reqwest::Error),
    #[error("Time error: `{0}`")]
    TimeError(#[from] time::error::Format),
    #[error("URL parse error: `{0}`")]
    UrlParseError(#[from] url::ParseError),
}

type ArcIri = sophia_api::prelude::Iri<Arc<str>>;
type JsonParseError = Meta<json_syntax::parse::Error<Location<ArcIri>>, Location<ArcIri>>;

impl Loader<ArcIri, Location<ArcIri>> for CachingLoader {
    type Output = json_syntax::Value<Location<ArcIri>>;
    type Error = CachingLoaderError;

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
            let context = self.load_context(url.as_str()).await?;

            let doc = json_syntax::Value::parse_str(&context, |span| {
                Location::new(url.to_owned(), span)
            })?;

            Ok(RemoteDocument::new(
                Some(url.to_owned()),
                Some("application/ld+json".parse()?),
                doc,
            ))
        }
        .boxed()
    }
}

impl CachingLoader {
    pub async fn load_context(&self, url: &str) -> Result<String, CachingLoaderError> {
        let result = self
            .json_ld_context_repository
            .get_json_ld_context_by_url(url)
            .await?;

        let context = match result {
            None => {
                let context_str = match self.fetch_context(url, None).await? {
                    FetchContextResult::LastModifiedHeader(_) => {
                        Err(CachingLoaderError::ReceivedStatus3xxInsteadOf2xx)
                    }
                    FetchContextResult::Value(context_str) => Ok(context_str),
                }?;

                let now = OffsetDateTime::now_utc();
                let context = JsonLdContext {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    context: context_str.to_owned().into_bytes(),
                    url: url.parse()?,
                    hit_counter: 0,
                };

                self.json_ld_context_repository
                    .create_json_ld_context(context)
                    .await?;

                context_str
            }
            Some(mut context) => {
                if self.context_requires_update(context.last_modified) {
                    let current_context_str = String::from_utf8(context.context.to_owned())?;
                    let (context_str, last_modified) =
                        match self.fetch_context(url, Some(context.last_modified)).await? {
                            FetchContextResult::LastModifiedHeader(last_modified) => {
                                (current_context_str, last_modified)
                            }
                            FetchContextResult::Value(context_str) => {
                                (context_str, OffsetDateTime::now_utc())
                            }
                        };

                    context.last_modified = last_modified;
                    context.context = context_str.into_bytes();
                }
                context.hit_counter = context.hit_counter.to_owned() + 1;

                self.json_ld_context_repository
                    .update_json_ld_context(context.to_owned())
                    .await?;

                String::from_utf8(context.context)?
            }
        };

        self.clean_old_context_if_needed().await?;

        Ok(context)
    }

    async fn clean_old_context_if_needed(&self) -> Result<(), DataLayerError> {
        if self
            .json_ld_context_repository
            .get_repository_size()
            .await?
            > self.cache_size
        {
            self.json_ld_context_repository
                .delete_oldest_context()
                .await?;
        }

        Ok(())
    }

    fn context_requires_update(&self, last_modified: OffsetDateTime) -> bool {
        let now = OffsetDateTime::now_utc();

        last_modified + self.cache_refresh_timeout < now
    }

    async fn fetch_context(
        &self,
        url: &str,
        last_modified: Option<OffsetDateTime>,
    ) -> Result<FetchContextResult, CachingLoaderError> {
        let mut request = self.client.get(url);
        if let Some(last_modified) = last_modified {
            request = request.header(
                "If-Modified-Since",
                last_modified
                    .to_offset(offset!(+0))
                    .format(&RFC_2822_BUT_WITH_GMT)?,
            );
        }

        let response = request.send().await?.error_for_status()?;
        let status = response.status();
        if status.is_success() {
            Ok(FetchContextResult::Value(response.text().await?))
        } else if status.is_redirection() {
            let result = response
                .headers()
                .get("Last-Modified")
                .ok_or(CachingLoaderError::ReceivedStatus304WithoutLastModifiedHeader)?
                .to_str()
                .map_err(|_| CachingLoaderError::CannotParseLastModifiedHeader)?;
            let last_modified = OffsetDateTime::parse(result, &Rfc2822)?;
            Ok(FetchContextResult::LastModifiedHeader(last_modified))
        } else {
            Err(CachingLoaderError::UnexpectedStatusCode(status.to_string()))
        }
    }
}

enum FetchContextResult {
    LastModifiedHeader(OffsetDateTime),
    Value(String),
}

const RFC_2822_BUT_WITH_GMT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

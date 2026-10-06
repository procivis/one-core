use axum::extract::FromRequestParts;
use axum::http;
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use headers::{Error, Header, Mime};
use serde_qs::Config;
use standardized_types::oauth2::TokenType;

pub struct Qs<T>(pub T);

impl<S, T> FromRequestParts<S> for Qs<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts
            .uri
            .query()
            .ok_or((StatusCode::BAD_REQUEST, "Query missing".to_string()))?;
        Ok(Self(deserialize(query)?))
    }
}

pub struct QsOpt<T>(pub T);

impl<S, T> FromRequestParts<S> for QsOpt<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned + Default,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(query) = parts.uri.query() else {
            return Ok(Self(Default::default()));
        };
        Ok(Self(deserialize(query)?))
    }
}

fn deserialize<T>(query: &str) -> Result<T, (StatusCode, String)>
where
    T: serde::de::DeserializeOwned,
{
    Config::new(2, false)
        .deserialize_bytes(query.as_bytes())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Query extraction error: {e}"),
            )
        })
}

#[derive(Clone, Debug, PartialEq)]
pub struct Accept(Vec<Mime>);

impl Accept {
    pub fn contains(&self, mime: &Mime) -> bool {
        self.0.contains(mime)
    }

    /// Most preferred media type by the client, if any.
    pub fn negotiate<T: Clone>(&self, supported: &[(&Mime, T)]) -> Option<T> {
        self.negotiate_all(supported).into_iter().next()
    }

    /// All acceptable media types specified by the client in descending order.
    pub fn negotiate_all<T: Clone>(&self, supported: &[(&Mime, T)]) -> Vec<T> {
        let mut acceptable: Vec<(usize, f32, &T)> = supported
            .iter()
            .filter_map(|(supported, value)| {
                let (position, quality) = self.best_match(supported)?;
                (quality > 0.0).then_some((position, quality, value))
            })
            .collect();

        // most preferred first; media types the client values equally keep the order in
        // which it listed them and, for those matched by the same header entry, the
        // order of `supported` (the sort is stable)
        acceptable.sort_by(
            |(left_position, left_quality, _), (right_position, right_quality, _)| {
                right_quality
                    .total_cmp(left_quality)
                    .then(left_position.cmp(right_position))
            },
        );

        acceptable
            .into_iter()
            .map(|(_, _, value)| value.clone())
            .collect()
    }

    /// Position within the header and quality value of the most specific media range
    /// matching `mime`, or `None` if the client did not list any range matching it.
    ///
    /// The most specific range wins independently of the order, as required by RFC 9110,
    /// so that e.g. `application/json;q=0, */*` accepts everything but JSON.
    fn best_match(&self, mime: &Mime) -> Option<(usize, f32)> {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, accepted)| matches(accepted, mime))
            .fold(
                None,
                |best: Option<(usize, &Mime)>, (position, accepted)| match best {
                    Some((_, best_accepted))
                        if specificity(best_accepted) >= specificity(accepted) =>
                    {
                        best
                    }
                    _ => Some((position, accepted)),
                },
            )
            .map(|(position, accepted)| (position, quality(accepted)))
    }
}

fn quality(mime: &Mime) -> f32 {
    mime.get_param("q")
        .and_then(|q| q.as_str().parse().ok())
        .unwrap_or(1.0)
}

fn specificity(mime: &Mime) -> u8 {
    match (mime.type_() == mime::STAR, mime.subtype() == mime::STAR) {
        (true, _) => 0,
        (false, true) => 1,
        (false, false) => 2,
    }
}

fn matches(accepted: &Mime, supported: &Mime) -> bool {
    (accepted.type_() == mime::STAR || accepted.type_() == supported.type_())
        && (accepted.subtype() == mime::STAR || accepted.subtype() == supported.subtype())
}

impl Header for Accept {
    fn name() -> &'static HeaderName {
        &http::header::ACCEPT
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        // repeating the header is equivalent to listing the media types in a single one
        let types = values
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|s| s.trim())
            .flat_map(|s| s.parse::<Mime>().ok().into_iter())
            .collect::<Vec<Mime>>();

        if types.is_empty() {
            return Err(Error::invalid());
        }

        Ok(Accept(types))
    }

    #[allow(clippy::expect_used)]
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let value = self
            .0
            .iter()
            .map(|m| m.as_ref())
            .collect::<Vec<_>>()
            .join(", ")
            .parse()
            .expect("Mime list is always a valid HeaderValue");
        values.extend([value]);
    }
}

/// A request without an `Accept` header accepts any media type
/// (RFC 9110, section 12.5.1). Handlers take `Option<TypedHeader<Accept>>` and fall back
/// to this; a header that is present but invalid is still rejected by the extractor.
impl Default for Accept {
    fn default() -> Self {
        Self::from(mime::STAR_STAR)
    }
}

impl From<Mime> for Accept {
    fn from(m: Mime) -> Accept {
        Accept(vec![m])
    }
}

pub struct AccessToken {
    pub scheme: TokenType,
    pub token: String,
}

impl Header for AccessToken {
    fn name() -> &'static HeaderName {
        &http::header::AUTHORIZATION
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let (scheme, token) = values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .ok_or_else(Error::invalid)?;
        let scheme = if scheme.eq_ignore_ascii_case("Bearer") {
            TokenType::Bearer
        } else if scheme.eq_ignore_ascii_case("DPoP") {
            TokenType::DPoP
        } else {
            return Err(Error::invalid());
        };
        Ok(Self {
            scheme,
            token: token.trim().to_string(),
        })
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(HeaderValue::from_str(&format!(
            "{} {}",
            self.scheme, self.token
        )));
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    fn accept(value: &str) -> Accept {
        let header = HeaderValue::from_str(value).unwrap();
        Accept::decode(&mut [&header].into_iter()).unwrap()
    }

    fn negotiate(value: &str) -> Option<&'static str> {
        let jwt: Mime = "application/jwt".parse().unwrap();
        accept(value).negotiate(&[(&mime::APPLICATION_JSON, "json"), (&jwt, "jwt")])
    }

    #[test]
    fn test_negotiate_respects_header_order() {
        assert_eq!(Some("json"), negotiate("application/json, application/jwt"));
        assert_eq!(Some("jwt"), negotiate("application/jwt, application/json"));
        assert_eq!(
            Some("jwt"),
            negotiate("text/plain, application/jwt, application/json")
        );
    }

    #[test]
    fn test_negotiate_respects_quality_values() {
        assert_eq!(
            Some("jwt"),
            negotiate("application/json;q=0.5, application/jwt;q=0.9")
        );
        assert_eq!(
            Some("json"),
            negotiate("application/jwt;q=0.5, application/json")
        );
        assert_eq!(
            Some("jwt"),
            negotiate("application/json;q=0, application/jwt")
        );
        assert_eq!(None, negotiate("application/json;q=0"));
        // the more specific range decides, independently of the order
        assert_eq!(Some("jwt"), negotiate("application/json;q=0, */*"));
        assert_eq!(Some("jwt"), negotiate("*/*, application/json;q=0"));
    }

    #[test]
    fn test_negotiate_wildcards_fall_back_to_server_preference() {
        assert_eq!(Some("json"), negotiate("*/*"));
        assert_eq!(Some("json"), negotiate("application/*"));
        assert_eq!(Some("jwt"), negotiate("application/jwt, */*"));
        assert_eq!(Some("jwt"), negotiate("*/*;q=0.5, application/jwt"));
    }

    #[test]
    fn test_negotiate_all_returns_acceptable_types_in_order_of_preference() {
        let negotiate_all = |value: &str| {
            let jwt: Mime = "application/jwt".parse().unwrap();
            accept(value).negotiate_all(&[(&mime::APPLICATION_JSON, "json"), (&jwt, "jwt")])
        };

        assert_eq!(vec!["json", "jwt"], negotiate_all("*/*"));
        assert_eq!(
            vec!["jwt", "json"],
            negotiate_all("application/jwt, application/json")
        );
        assert_eq!(
            vec!["jwt", "json"],
            negotiate_all("application/json;q=0.5, application/jwt")
        );
        // the wildcard adds the remaining type without repeating the preferred one
        assert_eq!(vec!["jwt", "json"], negotiate_all("application/jwt, */*"));
        assert_eq!(vec!["jwt"], negotiate_all("application/json;q=0, */*"));
        assert_eq!(Vec::<&str>::new(), negotiate_all("text/plain"));
    }

    #[test]
    fn test_default_accept_accepts_any_media_type() {
        assert_eq!(
            Some("json"),
            Accept::default().negotiate(&[(&mime::APPLICATION_JSON, "json")])
        );
    }

    #[test]
    fn test_negotiate_unsupported_media_type() {
        assert_eq!(None, negotiate("text/plain"));
        assert_eq!(None, negotiate("text/*, application/xml"));
    }

    #[test]
    fn test_access_token_schemes() {
        let decode = |value: &'static str| {
            AccessToken::decode(&mut [&HeaderValue::from_static(value)].into_iter())
        };

        let token = decode("Bearer abc").unwrap();
        assert_eq!(
            (TokenType::Bearer, "abc"),
            (token.scheme, token.token.as_str())
        );
        let token = decode("dpop abc").unwrap();
        assert_eq!(
            (TokenType::DPoP, "abc"),
            (token.scheme, token.token.as_str())
        );
        assert!(decode("Basic abc").is_err());
        assert!(decode("abc").is_err());
    }
}

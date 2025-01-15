use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use serde_qs::Config;

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

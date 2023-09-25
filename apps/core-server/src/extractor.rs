use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use serde_qs::Config;

pub struct Qs<T>(pub T);

#[async_trait]
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
        Ok(Self(
            Config::new(0, false)
                .deserialize_bytes(query.as_bytes())
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Query extraction error: {e}"),
                    )
                })?,
        ))
    }
}

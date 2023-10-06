use crate::{model::common::GetListResponse, service::error::ServiceError};

pub fn vector_into<T, F: Into<T>>(input: Vec<F>) -> Vec<T> {
    input.into_iter().map(|item| item.into()).collect()
}

pub fn vector_try_into<T, F: TryInto<T>>(
    input: Vec<F>,
) -> Result<Vec<T>, <F as TryInto<T>>::Error> {
    input.into_iter().map(|item| item.try_into()).collect()
}

// not needed for now, uncomment if necessary
// pub fn vector_ref_into<T, F: Into<T> + Clone>(input: &[F]) -> Vec<T> {
//     input.iter().map(|item| item.clone().into()).collect()
// }

pub fn list_response_into<T, F: Into<T>>(input: GetListResponse<F>) -> GetListResponse<T> {
    GetListResponse::<T> {
        values: vector_into(input.values),
        total_pages: input.total_pages,
        total_items: input.total_items,
    }
}

pub fn list_response_try_into<T, F: TryInto<T>>(
    input: GetListResponse<F>,
) -> Result<GetListResponse<T>, <F as TryInto<T>>::Error> {
    Ok(GetListResponse::<T> {
        values: vector_try_into(input.values)?,
        total_pages: input.total_pages,
        total_items: input.total_items,
    })
}

pub fn get_base_url(url: &str) -> Result<String, ServiceError> {
    let url_parsed = reqwest::Url::parse(url).map_err(|_| ServiceError::IncorrectParameters)?;

    let mut host_url = format!(
        "{}://{}",
        url_parsed.scheme(),
        url_parsed
            .host_str()
            .ok_or(ServiceError::IncorrectParameters)?
    );

    if let Some(port) = url_parsed.port() {
        host_url.push_str(&format!(":{port}"));
    }

    Ok(host_url)
}

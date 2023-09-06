use crate::model::common::GetListResponse;

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

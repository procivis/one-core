use crate::config::core_config::DatatypeType;
use crate::service::error::ServiceError;

pub(super) fn to_swiyu_data_type(data_type: DatatypeType) -> Result<&'static str, ServiceError> {
    Ok(match data_type {
        DatatypeType::String => "string",
        DatatypeType::Number => "numeric",
        DatatypeType::Date => "datetime",
        DatatypeType::SwiyuPicture => "image/jpeg",
        DatatypeType::Boolean => "bool",
        _ => {
            return Err(ServiceError::MappingError(format!(
                "Unsupported data type: {data_type:?}"
            )));
        }
    })
}

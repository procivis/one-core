use crate::config::core_config::DatatypeType;
use crate::service::oid4vci_final1_0::error::OID4VCIFinal1_0ServiceError;

pub(super) fn to_swiyu_data_type(
    data_type: DatatypeType,
) -> Result<&'static str, OID4VCIFinal1_0ServiceError> {
    Ok(match data_type {
        // Swiyu handling of data and booleans is different in the iOS and Android wallets so it is
        // declared as string.
        DatatypeType::String | DatatypeType::Date | DatatypeType::Boolean => "string",
        DatatypeType::Number => "numeric",
        DatatypeType::SwiyuPicture => "image/jpeg",
        _ => {
            return Err(OID4VCIFinal1_0ServiceError::MappingError(format!(
                "Unsupported data type: {data_type:?}"
            )));
        }
    })
}

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::provider::credential_formatter::error::FormatterError;

// TODO Replace with a trait impl or something a bit less tedious for conversion.
pub fn convert_params<T, R>(input: T) -> Result<R, FormatterError>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let result = serde_json::to_value(input).map_err(|e| FormatterError::Failed(e.to_string()))?;
    serde_json::from_value(result).map_err(|e| FormatterError::Failed(e.to_string()))
}

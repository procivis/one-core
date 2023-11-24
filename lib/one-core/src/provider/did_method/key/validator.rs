use crate::provider::did_method::{key::mapper::DidKeyType, DidMethodError};

pub(super) fn validate_public_key_length(
    public_key: &[u8],
    key_type: DidKeyType,
) -> Result<(), DidMethodError> {
    let is_correct_length = match key_type {
        DidKeyType::Eddsa => public_key.len() == 32,
        DidKeyType::Es256 => public_key.len() == 33,
    };

    if is_correct_length {
        Ok(())
    } else {
        Err(DidMethodError::ResolutionError(
            "Invalid key length".to_string(),
        ))
    }
}

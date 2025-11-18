use super::dto::Params;
use crate::config::core_config::KeySecurityLevelFields;

pub(super) fn params_from_fields(
    fields: &KeySecurityLevelFields,
) -> Result<Params, serde_json::Error> {
    let merged = fields.params.as_ref().and_then(|params| params.merge());
    if let Some(params) = merged {
        return serde_json::from_value(params);
    }
    Ok(Params::default())
}

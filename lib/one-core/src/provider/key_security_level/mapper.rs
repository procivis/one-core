use super::dto::HolderParams;
use crate::config::core_config::KeySecurityLevelFields;

pub(super) fn holder_params_from_fields(
    fields: &KeySecurityLevelFields,
) -> Result<HolderParams, serde_json::Error> {
    if let Some(params) = &fields.params
        && let Some(public) = &params.public
        && let Some(holder_params) = public.get("holder")
    {
        return serde_json::from_value(holder_params.clone());
    }

    Ok(HolderParams::default())
}

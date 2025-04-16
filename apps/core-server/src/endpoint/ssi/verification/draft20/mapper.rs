use one_core::provider::verification_protocol::openid4vp::model::PresentationSubmissionMappingDTO;

use super::dto::InternalPresentationSubmissionMappingRestDTO;

impl From<InternalPresentationSubmissionMappingRestDTO> for PresentationSubmissionMappingDTO {
    fn from(value: InternalPresentationSubmissionMappingRestDTO) -> Self {
        Self {
            id: value.presentation_submission.id,
            definition_id: value.presentation_submission.definition_id,
            descriptor_map: value
                .presentation_submission
                .descriptor_map
                .into_iter()
                .map(|p| p.into())
                .collect(),
        }
    }
}

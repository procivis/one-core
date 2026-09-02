use one_core::service::common_dto::TrustInformationDetailResponseDTO;
use one_core::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimValueResponseDTO,
    DetailCredentialSchemaResponseDTO,
};
use one_core::service::credential_schema::dto::CredentialSchemaListItemV2ResponseDTO;
use one_dto_mapper::{convert_inner, convert_inner_of_inner, try_convert_inner};

use super::dto::{
    CredentialDetailClaimValueResponseRestDTO, CredentialDetailSchemaResponseRestDTO,
    CredentialListItemSchemaRestDTO, CredentialTrustInformationDetailResponseRestDTO,
    GetCredentialResponseRestDTO,
};
use crate::dto::common::trust_detail::TrustInformationDetailResponseRestEnum;
use crate::mapper::MapperError;

impl<IN, OUT: From<IN>> TryFrom<CredentialDetailResponseDTO<IN>>
    for GetCredentialResponseRestDTO<OUT>
{
    type Error = MapperError;

    fn try_from(value: CredentialDetailResponseDTO<IN>) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            revocation_date: value.revocation_date,
            expires_at: value.expires_at,
            consumed_at: value.consumed_at,
            state: value.state.into(),
            r#type: value.r#type.into(),
            remaining_batch_item_count: value.remaining_batch_item_count,
            last_modified: value.last_modified,
            schema: value.schema.into(),
            issuer: convert_inner(value.issuer),
            issuer_certificate: try_convert_inner(value.issuer_certificate)?,
            claims: convert_inner(value.claims),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            interaction_id: value.interaction_id,
            suspend_end_date: value.suspend_end_date,
            mdoc_mso_validity: convert_inner(value.mdoc_mso_validity),
            holder: convert_inner(value.holder),
            protocol: value.protocol,
            profile: value.profile,
            wallet_instance_attestation: convert_inner(value.wallet_instance_attestation),
            wallet_unit_attestation: convert_inner(value.wallet_unit_attestation),
            webhook_destination_url: value.webhook_destination_url,
            trust_information: value.trust_information.map(Into::into),
            parent_id: value.parent_id,
            subscriber_information: value.subscriber_information,
            ecosystem: value.ecosystem,
            offered_formats: convert_inner_of_inner(value.offered_formats),
        })
    }
}

impl<IN, OUT: From<IN>> From<DetailCredentialClaimValueResponseDTO<IN>>
    for CredentialDetailClaimValueResponseRestDTO<OUT>
{
    fn from(value: DetailCredentialClaimValueResponseDTO<IN>) -> Self {
        match value {
            DetailCredentialClaimValueResponseDTO::Boolean(val) => Self::Boolean(val),
            DetailCredentialClaimValueResponseDTO::Float(val) => Self::Float(val),
            DetailCredentialClaimValueResponseDTO::Integer(val) => Self::Integer(val),
            DetailCredentialClaimValueResponseDTO::String(val) => Self::String(val),
            DetailCredentialClaimValueResponseDTO::Nested(nested) => {
                Self::Nested(convert_inner(nested))
            }
        }
    }
}

impl From<TrustInformationDetailResponseDTO> for CredentialTrustInformationDetailResponseRestDTO {
    fn from(value: TrustInformationDetailResponseDTO) -> Self {
        let issuer = convert_inner(value.issuer);

        let eudi_ecosystem =
            if let Some(TrustInformationDetailResponseRestEnum::Eudi(eudi_issuer)) = &issuer {
                Some(eudi_issuer.to_owned())
            } else {
                None
            };

        Self {
            #[expect(deprecated)]
            eudi_ecosystem,
            ecosystem: value.ecosystem,
            issuer,
        }
    }
}

impl From<CredentialSchemaListItemV2ResponseDTO> for CredentialListItemSchemaRestDTO {
    fn from(value: CredentialSchemaListItemV2ResponseDTO) -> Self {
        let single_format = if value.formats.len() == 1 {
            value.formats.first()
        } else {
            None
        };

        Self {
            #[expect(deprecated)]
            revocation_method: value.revocation_method.to_owned(),
            #[expect(deprecated)]
            format: single_format.map(|f| f.format.to_owned()),
            #[expect(deprecated)]
            schema_id: single_format.map(|f| f.ecosystem_schema_id.to_owned()),
            schema: value.into(),
        }
    }
}

impl From<DetailCredentialSchemaResponseDTO> for CredentialDetailSchemaResponseRestDTO {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        let list_item: CredentialListItemSchemaRestDTO = value.schema.into();

        Self {
            organisation_id: value.organisation_id,
            #[expect(deprecated)]
            revocation_method: list_item.revocation_method,
            #[expect(deprecated)]
            format: list_item.format,
            #[expect(deprecated)]
            schema_id: list_item.schema_id,
            schema: list_item.schema,
        }
    }
}

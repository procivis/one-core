use one_core::model::key::PublicKeyJwk;
use one_core::provider::exchange_protocol::openid4vc::error::OpenID4VCIError;
use one_core::provider::exchange_protocol::openid4vc::model::{
    OpenID4VCICredentialOfferClaimValue, OpenID4VCITokenRequestDTO, Timestamp,
};
use one_core::service::error::ServiceError;
use one_core::service::key::dto::PublicKeyJwkDTO;
use one_dto_mapper::convert_inner;

use super::dto::{
    OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO, OpenID4VCITokenRequestRestDTO,
    PublicKeyJwkRestDTO, TimestampRest,
};
use crate::endpoint::ssi::dto::{
    OpenID4VCICredentialOfferClaimValueDTO, OpenID4VCIErrorResponseRestDTO,
};

impl From<OpenID4VCIError> for OpenID4VCIErrorResponseRestDTO {
    fn from(value: OpenID4VCIError) -> Self {
        Self {
            error: value.into(),
        }
    }
}

impl From<Timestamp> for TimestampRest {
    fn from(value: Timestamp) -> Self {
        Self(value.0)
    }
}

impl From<OpenID4VCICredentialOfferClaimValue> for OpenID4VCICredentialOfferClaimValueDTO {
    fn from(value: OpenID4VCICredentialOfferClaimValue) -> Self {
        match value {
            OpenID4VCICredentialOfferClaimValue::Nested(nested) => {
                OpenID4VCICredentialOfferClaimValueDTO::Nested(convert_inner(nested))
            }
            OpenID4VCICredentialOfferClaimValue::String(value) => {
                OpenID4VCICredentialOfferClaimValueDTO::String(value)
            }
        }
    }
}

impl TryFrom<OpenID4VCITokenRequestRestDTO> for OpenID4VCITokenRequestDTO {
    type Error = ServiceError;

    fn try_from(value: OpenID4VCITokenRequestRestDTO) -> Result<Self, Self::Error> {
        match (
            value.grant_type.as_str(),
            value.pre_authorized_code,
            value.refresh_token,
        ) {
            (
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                Some(pre_authorized_code),
                None,
            ) => Ok(Self::PreAuthorizedCode {
                pre_authorized_code,
            }),
            ("refresh_token", None, Some(refresh_token)) => {
                Ok(Self::RefreshToken { refresh_token })
            }
            ("urn:ietf:params:oauth:grant-type:pre-authorized_code" | "refresh_token", _, _) => {
                Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidRequest,
                ))
            }
            (grant, _, _) if !grant.is_empty() => Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::UnsupportedGrantType,
            )),
            _ => Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            )),
        }
    }
}

impl From<PublicKeyJwk> for PublicKeyJwkRestDTO {
    fn from(value: PublicKeyJwk) -> Self {
        PublicKeyJwkDTO::from(value).into()
    }
}

impl utoipa::PartialSchema for OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new().property("value",utoipa::openapi::ObjectBuilder::new().property_names(Some(utoipa::openapi::ObjectBuilder::new().schema_type(utoipa::openapi::schema::SchemaType::new(utoipa::openapi::schema::Type::String)))).additional_properties(Some(utoipa::openapi::schema::RefBuilder::new().ref_location_from_schema_name(format!("{}", <OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO as utoipa::ToSchema> ::name()))))).property("value_type",utoipa::openapi::ObjectBuilder::new().schema_type(utoipa::openapi::schema::SchemaType::new(utoipa::openapi::schema::Type::String))).required("value_type").property("mandatory",utoipa::openapi::ObjectBuilder::new().schema_type({
            use std::iter::FromIterator;
            utoipa::openapi::schema::SchemaType::from_iter([utoipa::openapi::schema::Type::Boolean,utoipa::openapi::schema::Type::Null])
        })).property("order",utoipa::openapi::schema::ArrayBuilder::new().schema_type({
            use std::iter::FromIterator;
            utoipa::openapi::schema::SchemaType::from_iter([utoipa::openapi::schema::Type::Array,utoipa::openapi::schema::Type::Null])
        }).items(utoipa::openapi::ObjectBuilder::new().schema_type(utoipa::openapi::schema::SchemaType::new(utoipa::openapi::schema::Type::String)))).property("array",utoipa::openapi::ObjectBuilder::new().schema_type({
            use std::iter::FromIterator;
            utoipa::openapi::schema::SchemaType::from_iter([utoipa::openapi::schema::Type::Boolean,utoipa::openapi::schema::Type::Null])
        })).into()
    }
}

impl utoipa::ToSchema for OpenID4VCIIssuerMetadataMdocClaimsValuesRestDTO {}

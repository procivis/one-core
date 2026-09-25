use std::fmt::Display;

use super::{
    ClaimPath, ClaimQueryId, ClaimValue, CredentialFormat, CredentialQueryId, PathSegment,
};

impl Display for CredentialQueryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for ClaimQueryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for ClaimPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let elements = self
            .segments
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "[{elements}]")
    }
}

impl Display for PathSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathSegment::PropertyName(name) => write!(f, "\"{name}\""),
            PathSegment::ArrayIndex(idx) => write!(f, "{idx}"),
            PathSegment::ArrayAll => write!(f, "null"),
        }
    }
}

impl Display for CredentialFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialFormat::MsoMdoc(meta) => {
                write!(f, "mso_mdoc(doctype: {})", meta.doctype_value)
            }
            CredentialFormat::SdJwtVc(meta) => {
                write!(f, "dc+sd-jwt(vct_types: {:?})", meta.vct_values)
            }
            CredentialFormat::LdpVc(meta) => {
                write!(f, "ldp_vc(type_values: {:?})", meta.type_values)
            }
            CredentialFormat::JwtVc(meta) => {
                write!(f, "jwt_vc_json(type_values: {:?})", meta.type_values)
            }
            CredentialFormat::W3cSdJwt(meta) => {
                write!(f, "vc+sd-jwt(type_values: {:?})", meta.type_values)
            }
        }
    }
}

impl Display for ClaimValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(name) => write!(f, "\"{name}\""),
            Self::Integer(value) => write!(f, "{value}"),
            Self::Boolean(value) => write!(f, "{value}"),
        }
    }
}

use std::fmt::Display;

use crate::{
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
            CredentialFormat::MsoMdoc => write!(f, "mso_mdoc"),
            CredentialFormat::LdpVc => write!(f, "ldp_vc"),
            CredentialFormat::JwtVc => write!(f, "jwt_vc_json"),
            CredentialFormat::SdJwt => write!(f, "dc+sd-jwt"),
            CredentialFormat::W3cSdJwt => write!(f, "vc+sd-jwt"),
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

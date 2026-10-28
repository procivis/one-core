use serde::de::Error;
use serde::{Deserialize, Deserializer};
use standardized_types::etsi_119_475::registration_certificate::{
    Intermediary, Payload, Subject, SupervisoryAuthority,
};
use standardized_types::etsi_119_475::{Credential, Entitlement, EntitlementRole, MultiLangString};
use standardized_types::eudi_ts2::{Policy, PolicyType};
use url::Url;

use crate::proto::jwt::Jwt;

// Payload specification according to spec from:
// https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
// The payload types themselves live in `standardized_types::etsi_119_475`; what remains here is
// the shape of the signing request accepted by this provider, which is not part of the standard.

pub type WRPRegistrationCertificate = Jwt<Payload>;
pub type WRPRegistrationCertificatePayload = crate::proto::jwt::model::JWTPayload<Payload>;

/// Request data for a `REGISTRATION_CERTIFICATE` signer, after
/// deserialization and validation. Built from the `data` field of a
/// signature request; see `RequestDataProto` in the `Deserialize` impl
/// for the wire format.
///
/// Field names follow the claim names of ETSI TS 119 475 clause 5.2.4,
/// except where the wire format renames them: `sub`, `service`, `dpa`,
/// and `act`.
///
/// Validation:
/// - At least one entitlement is required (GEN-5.2.4-03).
/// - If any entitlement has the service provider role, `credentials`,
///   `purpose`, and `intended_use_id` are required (GEN-5.2.4-06).
/// - `privacy_policy` must include a policy of type privacy policy.
#[derive(Debug)]
pub struct RequestData {
    pub name: String,
    /// The relying party. Its `id` becomes the JWT `sub` claim; its names
    /// become `sub_ln`, or `sub_gn` and `sub_fn`.
    pub subject: Subject,
    pub country: String,
    pub registry_uri: Url,
    /// Becomes the `srv_description` claim.
    pub service_description: Vec<MultiLangString>,
    pub entitlements: Vec<Entitlement>,
    /// URI of the first privacy policy of type privacy policy. Other
    /// policies in the request are dropped.
    pub privacy_policy: Url,
    pub info_uri: Url,
    /// From `dpa` in the request.
    pub supervisory_authority: SupervisoryAuthority,
    pub policy_id: Vec<String>,
    pub certificate_policy: Url,
    /// Becomes the `provides_attestations` claim.
    pub provided_attestations: Option<Vec<Credential>>,
    pub credentials: Option<Vec<Credential>>,
    pub purpose: Option<Vec<MultiLangString>>,
    pub intended_use_id: Option<String>,
    pub public_body: Option<bool>,
    pub support_uri: Url,
    /// From `act` in the request.
    pub intermediary: Option<Intermediary>,
}

impl<'de> Deserialize<'de> for RequestData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Wire format of Registration Certificate request data.
        /// Unknown fields are rejected.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct RequestDataProto {
            /// The relying party's name, as shown to wallet users.
            pub name: String,
            /// The relying party: `{id, legal_name}` for a legal person or
            /// `{id, given_name, family_name}` for a natural person.
            #[serde(rename = "sub")]
            pub subject: Subject,
            /// Country code of the relying party.
            pub country: String,
            /// URI of the registry where the relying party is registered.
            pub registry_uri: Url,
            /// Description of the relying party's service, as
            /// language-tagged strings.
            #[serde(rename = "service")]
            pub service_description: Vec<MultiLangString>,
            /// Entitlements, each as an ETSI URI or OID label. At least one.
            pub entitlements: Vec<Entitlement>,
            /// Typed policies. Must include one of type privacy policy.
            pub privacy_policy: Vec<Policy>,
            /// URI with information about the relying party.
            pub info_uri: Url,
            /// Contact details of the supervising data protection
            /// authority.
            #[serde(rename = "dpa")]
            pub data_protection_authority: SupervisoryAuthority,
            /// Identifiers of the policies the certificate is issued under.
            pub policy_id: Vec<String>,
            /// URI of the registrar's certificate policy.
            pub certificate_policy: Url,
            /// Attestations the relying party issues. Note the claim name
            /// differs: `provides_attestations`.
            pub provided_attestations: Option<Vec<Credential>>,
            /// Credentials and claims the relying party may request.
            /// Required for service providers.
            pub credentials: Option<Vec<Credential>>,
            /// Why the relying party requests the credentials, as
            /// language-tagged strings. Required for service providers.
            pub purpose: Option<Vec<MultiLangString>>,
            /// Identifier of the registered intended use. Required for
            /// service providers.
            pub intended_use_id: Option<String>,
            /// Whether the relying party is a public sector body.
            pub public_body: Option<bool>,
            /// URI where wallet users can get support.
            pub support_uri: Url,
            /// Intermediary acting on behalf of the relying party.
            #[serde(rename = "act")]
            pub intermediary: Option<Intermediary>,
        }

        let proto = RequestDataProto::deserialize(deserializer)?;

        // GEN-5.2.4-03: The `entitlements` field specified in GEN-5.2.4-01 shall include
        // at least one entitlement specified in clause A.2.
        if proto.entitlements.is_empty() {
            return Err(Error::custom("Must provide at least one valid entitlement"));
        }

        // GEN-5.2.4-06: If the WRPRC is issued to the service provider
        // as specified in clause 4.2 the payload of the WRPRC shall include
        // all the fields provided by the registry specified in Table 9.
        let is_service_provider = proto
            .entitlements
            .iter()
            .any(|e| e.role == EntitlementRole::ServiceProvider);
        if is_service_provider {
            if proto.credentials.is_none() {
                return Err(Error::missing_field("credentials"));
            }
            if proto.purpose.is_none() {
                return Err(Error::missing_field("purpose"));
            }
            if proto.intended_use_id.is_none() {
                return Err(Error::missing_field("intended_use_id"));
            }
        }

        let privacy_policy = proto
            .privacy_policy
            .into_iter()
            .find(|policy| policy.r#type == PolicyType::PrivacyPolicy)
            .ok_or(Error::custom(
                "Must provide at least one policy of PrivacyPolicy type",
            ))?;

        Ok(Self {
            name: proto.name,
            subject: proto.subject,
            country: proto.country,
            registry_uri: proto.registry_uri,
            service_description: proto.service_description,
            entitlements: proto.entitlements,
            privacy_policy: privacy_policy.policy_uri,
            info_uri: proto.info_uri,
            supervisory_authority: proto.data_protection_authority,
            policy_id: proto.policy_id,
            certificate_policy: proto.certificate_policy,
            provided_attestations: proto.provided_attestations,
            credentials: proto.credentials,
            purpose: proto.purpose,
            intended_use_id: proto.intended_use_id,
            public_body: proto.public_body,
            support_uri: proto.support_uri,
            intermediary: proto.intermediary,
        })
    }
}

impl RequestData {
    pub fn get_subject_id(&self) -> &str {
        self.subject.id()
    }
}

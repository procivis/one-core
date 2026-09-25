use super::credential_query_builder::{self, IsUnset, SetFormat, SetMultiple, State};
use super::{
    CredentialFormat, CredentialQuery, CredentialQueryBuilder, MsoMdocMeta, SdJwtVcMeta, W3cVcMeta,
};

impl CredentialQuery {
    pub fn mso_mdoc(doctype_value: String) -> CredentialQueryBuilder<SetFormat> {
        Self::builder().format(CredentialFormat::MsoMdoc(MsoMdocMeta { doctype_value }))
    }

    pub fn sd_jwt_vc(vct_values: Vec<String>) -> CredentialQueryBuilder<SetFormat> {
        Self::builder().format(CredentialFormat::SdJwtVc(SdJwtVcMeta { vct_values }))
    }

    pub fn jwt_vc(type_values: Vec<Vec<String>>) -> CredentialQueryBuilder<SetFormat> {
        Self::builder().format(CredentialFormat::JwtVc(W3cVcMeta { type_values }))
    }

    pub fn ldp_vc(type_values: Vec<Vec<String>>) -> CredentialQueryBuilder<SetFormat> {
        Self::builder().format(CredentialFormat::LdpVc(W3cVcMeta { type_values }))
    }

    pub fn w3c_sd_jwt(type_values: Vec<Vec<String>>) -> CredentialQueryBuilder<SetFormat> {
        Self::builder().format(CredentialFormat::W3cSdJwt(W3cVcMeta { type_values }))
    }
}

impl<S: State> CredentialQueryBuilder<S>
where
    S::Multiple: IsUnset,
{
    pub fn multiple(self) -> CredentialQueryBuilder<SetMultiple<S>> {
        self.set_multiple_internal(true)
    }

    pub fn single(self) -> CredentialQueryBuilder<SetMultiple<S>> {
        self.set_multiple_internal(false)
    }
}

impl<S: State> CredentialQueryBuilder<S>
where
    S::RequireCryptographicHolderBinding: IsUnset,
{
    pub fn without_holder_binding(
        self,
    ) -> CredentialQueryBuilder<credential_query_builder::SetRequireCryptographicHolderBinding<S>>
    {
        self.set_require_cryptographic_holder_binding_internal(false)
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::super::*;
    use crate::x509::KeyIdentifier;

    #[test]
    fn test_mso_mdoc_credential_builder() {
        let credential = CredentialQuery::mso_mdoc("org.iso.18013.5.1.mDL".to_string())
            .claims(vec![
                ClaimQuery::builder()
                    .path(vec![
                        "org.iso.18013.5.1".to_string(),
                        "given_name".to_string(),
                    ])
                    .build(),
            ])
            .id("test_id")
            .multiple()
            .build();

        assert_eq!(credential.id, CredentialQueryId::from("test_id"));
        assert_eq!(credential.claims.as_ref().unwrap().len(), 1);

        match &credential.format {
            CredentialFormat::MsoMdoc(mdoc_meta) => {
                assert_eq!(mdoc_meta.doctype_value, "org.iso.18013.5.1.mDL");
            }
            _ => panic!("Expected MsoMdoc metadata"),
        }
    }

    #[test]
    fn test_mso_mdoc_credential_builder_with_claims() {
        let credential = CredentialQuery::mso_mdoc("org.iso.18013.5.1.mDL".to_string())
            .id("test_id")
            .claims(vec![
                ClaimQuery::builder()
                    .path(vec![
                        "org.iso.18013.5.1".to_string(),
                        "given_name".to_string(),
                    ])
                    .build(),
            ])
            .build();

        assert_eq!(credential.id, CredentialQueryId::from("test_id"));
        assert_eq!(credential.claims.as_ref().unwrap().len(), 1);

        match &credential.format {
            CredentialFormat::MsoMdoc(mdoc_meta) => {
                assert_eq!(mdoc_meta.doctype_value, "org.iso.18013.5.1.mDL");
            }
            _ => panic!("Expected MsoMdoc metadata"),
        }
    }

    #[test]
    fn test_sd_jwt_vc_credential_builder() {
        let credential =
            CredentialQuery::sd_jwt_vc(vec!["https://example.com/credential".to_string()])
                .id("test_id")
                .build();

        assert_eq!(credential.id, CredentialQueryId::from("test_id"));

        match &credential.format {
            CredentialFormat::SdJwtVc(sd_jwt_vc_meta) => {
                assert_eq!(sd_jwt_vc_meta.vct_values.len(), 1);
                assert_eq!(
                    sd_jwt_vc_meta.vct_values[0],
                    "https://example.com/credential"
                );
            }
            _ => panic!("Expected SdJwtVc metadata"),
        }
    }

    #[test]
    fn test_jwt_vc_json_credential_builder() {
        let credential = CredentialQuery::jwt_vc(vec![vec![
            "VerifiableCredential".to_string(),
            "UniversityDegreeCredential".to_string(),
        ]])
        .id("jwt_vc")
        .build();

        assert_eq!(credential.id, CredentialQueryId::from("jwt_vc"));

        match &credential.format {
            CredentialFormat::JwtVc(jwt_meta) => {
                assert_eq!(jwt_meta.type_values.len(), 1);
                assert_eq!(
                    jwt_meta.type_values[0],
                    vec!["VerifiableCredential", "UniversityDegreeCredential"]
                );
            }
            _ => panic!("Expected W3cVc metadata"),
        }
    }

    #[test]
    fn test_ldp_vc_credential_builder() {
        let credential = CredentialQuery::ldp_vc(vec![vec![
            "VerifiableCredential".to_string(),
            "DriverLicense".to_string(),
        ]])
        .id("ldp_vc")
        .build();

        assert_eq!(credential.id, CredentialQueryId::from("ldp_vc"));

        match &credential.format {
            CredentialFormat::LdpVc(ldp_vc_meta) => {
                assert_eq!(ldp_vc_meta.type_values.len(), 1);
                assert_eq!(
                    ldp_vc_meta.type_values[0],
                    vec!["VerifiableCredential", "DriverLicense"]
                );
            }
            _ => panic!("Expected W3cVc metadata"),
        }
    }

    #[test]
    fn test_w3c_sd_jwt_credential_builder() {
        let credential = CredentialQuery::w3c_sd_jwt(vec![vec![
            "VerifiableCredential".to_string(),
            "DriverLicense".to_string(),
        ]])
        .id("w3c_sd_jwt")
        .build();

        assert_eq!(credential.id, CredentialQueryId::from("w3c_sd_jwt"));

        match &credential.format {
            CredentialFormat::W3cSdJwt(sd_jwt_meta) => {
                assert_eq!(sd_jwt_meta.type_values.len(), 1);
                assert_eq!(
                    sd_jwt_meta.type_values[0],
                    vec!["VerifiableCredential", "DriverLicense"]
                );
            }
            _ => panic!("Expected W3cVc metadata"),
        }
    }

    #[test]
    fn test_dcql_query_builder_with_multiple_formats() {
        let mso_mdoc_cred = CredentialQuery::mso_mdoc("org.iso.18013.5.1.mDL".to_string())
            .id("mdoc_id")
            .build();

        let sd_jwt_cred =
            CredentialQuery::sd_jwt_vc(vec!["https://example.com/credential".to_string()])
                .id("sd_jwt_id")
                .build();

        let jwt_vc_cred = CredentialQuery::jwt_vc(vec![vec!["VerifiableCredential".to_string()]])
            .id("jwt_vc_id")
            .build();

        let w3c_sd_jwt_cred = CredentialQuery::w3c_sd_jwt(vec![vec![
            "VerifiableCredential".to_string(),
            "DriverLicense".to_string(),
        ]])
        .id("w3c_sd_jwt_id")
        .build();

        let query = DcqlQuery::builder()
            .credentials(vec![
                mso_mdoc_cred,
                sd_jwt_cred,
                jwt_vc_cred,
                w3c_sd_jwt_cred,
            ])
            .build();

        assert_eq!(query.credentials.len(), 4);
        assert!(matches!(
            query.credentials[0].format,
            CredentialFormat::MsoMdoc(_)
        ));
        assert!(matches!(
            query.credentials[1].format,
            CredentialFormat::SdJwtVc(_)
        ));
        assert!(matches!(
            query.credentials[2].format,
            CredentialFormat::JwtVc(_)
        ));
        assert!(matches!(
            query.credentials[3].format,
            CredentialFormat::W3cSdJwt(_)
        ));
    }

    #[test]
    fn test_claim_query_builder() {
        let claim = ClaimQuery::builder()
            .id("test_claim")
            .path(vec!["given_name".to_string()])
            .required(true)
            .intent_to_retain(false)
            .build();

        assert_eq!(claim.id, Some(ClaimQueryId::from("test_claim")));
        assert_eq!(claim.path, vec!["given_name"].into());
        assert_eq!(claim.required, Some(true));
        assert_eq!(claim.intent_to_retain, Some(false));
    }

    #[test]
    fn test_trusted_authorities_builder() {
        let credential = CredentialQuery::jwt_vc(vec![vec!["IDCredential".to_string()]])
            .id("with_ta")
            .trusted_authorities(vec![
                TrustedAuthority::EtsiTl {
                    values: vec!["https://lotl.example.com".to_string()],
                },
                TrustedAuthority::OpenidFederation {
                    values: vec!["https://trustanchor.example.com".to_string()],
                },
                TrustedAuthority::AuthorityKeyId {
                    values: vec![
                        KeyIdentifier::from_base64url("s9tIpPmhxdiuNkHMEWNpYim8S8Y").unwrap(),
                    ],
                },
                TrustedAuthority::Custom {
                    r#type: "custom".to_string(),
                    values: vec!["some-id".to_string()],
                },
            ])
            .build();

        let ta = credential.trusted_authorities.expect("present");
        assert_eq!(ta.len(), 4);
        assert!(matches!(ta[0], TrustedAuthority::EtsiTl { .. }));
        assert!(matches!(ta[1], TrustedAuthority::OpenidFederation { .. }));
        assert!(matches!(ta[2], TrustedAuthority::AuthorityKeyId { .. }));
        assert!(matches!(ta[3], TrustedAuthority::Custom { .. }));
    }

    #[test]
    fn test_withoug_holder_binding_builder() {
        let credential = CredentialQuery::jwt_vc(vec![vec!["IDCredential".to_string()]])
            .id("no_chb")
            .without_holder_binding()
            .build();

        assert_eq!(credential.require_cryptographic_holder_binding, false);
    }

    #[test]
    fn test_withoug_holder_binding_builder_default() {
        let credential = CredentialQuery::jwt_vc(vec![vec!["IDCredential".to_string()]])
            .id("no_chb")
            .build();

        assert_eq!(credential.require_cryptographic_holder_binding, true);
    }
}

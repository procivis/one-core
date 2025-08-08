use crate::credential_query_builder::{self, IsUnset, SetMultiple, State};
use crate::{CredentialFormat, CredentialMeta, CredentialQuery, CredentialQueryBuilder};

type SetMetaAndFormat = credential_query_builder::SetMeta<credential_query_builder::SetFormat>;

impl CredentialQuery {
    pub fn mso_mdoc(doctype_value: String) -> CredentialQueryBuilder<SetMetaAndFormat> {
        Self::builder()
            .format(CredentialFormat::MsoMdoc)
            .meta(CredentialMeta::MsoMdoc { doctype_value })
    }

    pub fn sd_jwt_vc(vct_values: Vec<String>) -> CredentialQueryBuilder<SetMetaAndFormat> {
        Self::builder()
            .format(CredentialFormat::SdJwt)
            .meta(CredentialMeta::SdJwtVc { vct_values })
    }

    pub fn jwt_vc(type_values: Vec<Vec<String>>) -> CredentialQueryBuilder<SetMetaAndFormat> {
        Self::builder()
            .format(CredentialFormat::JwtVc)
            .meta(CredentialMeta::W3cVc { type_values })
    }

    pub fn ldp_vc(type_values: Vec<Vec<String>>) -> CredentialQueryBuilder<SetMetaAndFormat> {
        Self::builder()
            .format(CredentialFormat::LdpVc)
            .meta(CredentialMeta::W3cVc { type_values })
    }

    pub fn w3c_sd_jwt(type_values: Vec<Vec<String>>) -> CredentialQueryBuilder<SetMetaAndFormat> {
        Self::builder()
            .format(CredentialFormat::W3cSdJwt)
            .meta(CredentialMeta::W3cVc { type_values })
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

impl<S: credential_query_builder::State> CredentialQueryBuilder<S>
where
    S::RequireCryptographicHolderBinding: credential_query_builder::IsUnset,
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

    use crate::{
        ClaimQuery, ClaimQueryId, CredentialFormat, CredentialMeta, CredentialQuery,
        CredentialQueryId, DcqlQuery,
    };

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
        assert_eq!(credential.format, CredentialFormat::MsoMdoc);
        assert_eq!(credential.claims.as_ref().unwrap().len(), 1);

        match &credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.18013.5.1.mDL");
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
        assert_eq!(credential.format, CredentialFormat::MsoMdoc);
        assert_eq!(credential.claims.as_ref().unwrap().len(), 1);

        match &credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.18013.5.1.mDL");
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
        assert_eq!(credential.format, CredentialFormat::SdJwt);

        match &credential.meta {
            CredentialMeta::SdJwtVc { vct_values } => {
                assert_eq!(vct_values.len(), 1);
                assert_eq!(vct_values[0], "https://example.com/credential");
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
        assert_eq!(credential.format, CredentialFormat::JwtVc);

        match &credential.meta {
            CredentialMeta::W3cVc { type_values } => {
                assert_eq!(type_values.len(), 1);
                assert_eq!(
                    type_values[0],
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
        assert_eq!(credential.format, CredentialFormat::LdpVc);

        match &credential.meta {
            CredentialMeta::W3cVc { type_values } => {
                assert_eq!(type_values.len(), 1);
                assert_eq!(
                    type_values[0],
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
        assert_eq!(credential.format, CredentialFormat::W3cSdJwt);

        match &credential.meta {
            CredentialMeta::W3cVc { type_values } => {
                assert_eq!(type_values.len(), 1);
                assert_eq!(
                    type_values[0],
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
        assert_eq!(query.credentials[0].format, CredentialFormat::MsoMdoc);
        assert_eq!(query.credentials[1].format, CredentialFormat::SdJwt);
        assert_eq!(query.credentials[2].format, CredentialFormat::JwtVc);
        assert_eq!(query.credentials[3].format, CredentialFormat::W3cSdJwt);
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
        use crate::TrustedAuthority;

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
                    values: vec!["s9tIpPmhxdiuNkHMEWNpYim8S8Y".to_string()],
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

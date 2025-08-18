use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::CredentialClaim;
use crate::provider::credential_formatter::sdjwt::model::VcClaim;
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};

pub(crate) fn vc_from_credential(
    mut credential: VcdmCredential,
    mut digests: Vec<String>,
    algorithm: &str,
) -> Result<VcClaim, FormatterError> {
    digests.sort_unstable();

    credential.credential_subject = vec![VcdmCredentialSubject {
        id: None,
        claims: indexmap::indexmap! {
          "_sd".to_string() => CredentialClaim::try_from(serde_json::json!(digests))?,
        },
    }];

    Ok(VcClaim {
        digests: vec![],
        vc: credential.into(),
        hash_alg: Some(algorithm.to_owned()),
    })
}

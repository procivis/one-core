use crate::config::core_config::FormatType;
use crate::error::ContextWithErrorCode;
use crate::mapper::RemoteIdentifierRelation;
use crate::model::credential::{
    Credential, CredentialCommon, IssuerIdentity, VerifierCredentialData,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::proto::identifier_creator::{IdentifierCreator, IdentifierName, IdentifierRole};
use crate::provider::verification_protocol::openid4vp::model::ProvedCredential;
use crate::service::error::ServiceError;

pub(crate) async fn credential_from_proved(
    identifier_creator: &dyn IdentifierCreator,
    proved_credential: ProvedCredential,
    organisation: &Related<Organisation>,
) -> Result<Credential, ServiceError> {
    let ProvedCredential {
        common,
        claims,
        format,
        issuer_details,
        holder_details,
    } = proved_credential;

    let (issuer_identifier, issuer_relation) = identifier_creator
        .get_or_create_remote_identifier(
            organisation.id(),
            &issuer_details,
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            None,
            None,
        )
        .await
        .error_while("creating remote issuer identifier")?;

    let issuer_certificate =
        if let RemoteIdentifierRelation::Certificate(certificate) = issuer_relation {
            Some(certificate.into())
        } else {
            None
        };

    let (holder_identifier, ..) = identifier_creator
        .get_or_create_remote_identifier(
            organisation.id(),
            &holder_details,
            IdentifierName::PrefixForId(IdentifierRole::Holder.to_string()),
            true,
            None,
            None,
        )
        .await
        .error_while("creating remote holder identifier")?;

    Ok(Credential::Verifier {
        common: CredentialCommon {
            expires_at: None,
            ecosystem: common.ecosystem,
            id: common.id,
            created_date: common.created_date,
            issuance_date: common.issuance_date,
            last_modified: common.last_modified,
            deleted_at: common.deleted_at,
            protocol: common.protocol,
            redirect_uri: common.redirect_uri,
            state: common.state,
            schema: from_provider_schema(
                common.schema.as_ref().await?.to_owned(),
                organisation.to_owned(),
            )
            .into(),
            interaction: None,
            profile: common.profile,
        },
        verifier_data: VerifierCredentialData {
            issuer: IssuerIdentity {
                identifier: issuer_identifier.into(),
                certificate: issuer_certificate,
            },
            claims,
            holder_identifier: Some(holder_identifier.into()),
            format,
        },
    })
}

fn from_provider_schema(
    schema: CredentialSchema,
    organisation: Related<Organisation>,
) -> CredentialSchema {
    CredentialSchema {
        organisation,
        ..schema
    }
}

pub(crate) fn format_type_to_dcql_format(format_type: &FormatType) -> String {
    match format_type {
        FormatType::Jwt => "jwt_vc_json",
        FormatType::SdJwt => "vc+sd-jwt",
        FormatType::SdJwtVc => "dc+sd-jwt",
        FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => "ldp_vc",
        FormatType::Mdoc => "mso_mdoc",
    }
    .to_string()
}

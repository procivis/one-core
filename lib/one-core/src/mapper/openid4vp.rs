use one_dto_mapper::convert_inner;

use crate::config::core_config::FormatType;
use crate::error::ContextWithErrorCode;
use crate::mapper::RemoteIdentifierRelation;
use crate::model::credential::{Credential, CredentialType};
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::proto::identifier_creator::{IdentifierCreator, IdentifierName, IdentifierRole};
use crate::provider::verification_protocol::openid4vp::model::ProvedCredential;
use crate::service::error::ServiceError;

pub(crate) async fn credential_from_proved(
    identifier_creator: &dyn IdentifierCreator,
    proved_credential: ProvedCredential,
    organisation: &Organisation,
) -> Result<Credential, ServiceError> {
    let (issuer_identifier, issuer_relation) = identifier_creator
        .get_or_create_remote_identifier(
            organisation,
            &proved_credential.issuer_details,
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
            organisation,
            &proved_credential.holder_details,
            IdentifierName::PrefixForId(IdentifierRole::Holder.to_string()),
            true,
            None,
            None,
        )
        .await
        .error_while("creating remote holder identifier")?;

    Ok(Credential {
        expires_at: None,
        ecosystem: proved_credential.credential.ecosystem,
        id: proved_credential.credential.id,
        created_date: proved_credential.credential.created_date,
        issuance_date: proved_credential.credential.issuance_date,
        last_modified: proved_credential.credential.last_modified,
        deleted_at: proved_credential.credential.deleted_at,
        consumed_at: None,
        protocol: proved_credential.credential.protocol,
        redirect_uri: proved_credential.credential.redirect_uri,
        role: proved_credential.credential.role,
        r#type: CredentialType::Single,
        state: proved_credential.credential.state,
        claims: proved_credential.credential.claims,
        issuer_identifier: Some(issuer_identifier.into()),
        issuer_certificate,
        holder_identifier: Some(holder_identifier.into()),
        schema: from_provider_schema(
            proved_credential
                .credential
                .schema
                .as_ref()
                .await?
                .to_owned(),
            organisation.to_owned(),
        )
        .into(),
        interaction: None,
        key: proved_credential.credential.key,
        suspend_end_date: convert_inner(proved_credential.credential.suspend_end_date),
        profile: proved_credential.credential.profile,
        credential_blob_id: proved_credential.credential.credential_blob_id,
        wallet_key_attestation_blob_id: proved_credential.credential.wallet_key_attestation_blob_id,
        wallet_instance_attestation_blob_id: proved_credential
            .credential
            .wallet_instance_attestation_blob_id,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: proved_credential.credential.format,
    })
}

fn from_provider_schema(schema: CredentialSchema, organisation: Organisation) -> CredentialSchema {
    CredentialSchema {
        organisation: organisation.into(),
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

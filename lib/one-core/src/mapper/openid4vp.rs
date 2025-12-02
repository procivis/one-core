use one_dto_mapper::{convert_inner, convert_inner_of_inner};

use crate::mapper::RemoteIdentifierRelation;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::proto::identifier_creator::{IdentifierCreator, IdentifierRole};
use crate::provider::verification_protocol::openid4vp::model::ProvedCredential;
use crate::service::error::ServiceError;

pub(crate) async fn credential_from_proved(
    identifier_creator: &dyn IdentifierCreator,
    proved_credential: ProvedCredential,
    organisation: &Organisation,
) -> Result<Credential, ServiceError> {
    let (issuer_identifier, issuer_relation) = identifier_creator
        .get_or_create_remote_identifier(
            &Some(organisation.to_owned()),
            &proved_credential.issuer_details,
            IdentifierRole::Issuer,
        )
        .await?;

    let issuer_certificate =
        if let RemoteIdentifierRelation::Certificate(certificate) = issuer_relation {
            Some(certificate)
        } else {
            None
        };

    let (holder_identifier, ..) = identifier_creator
        .get_or_create_remote_identifier(
            &Some(organisation.to_owned()),
            &proved_credential.holder_details,
            IdentifierRole::Holder,
        )
        .await?;

    Ok(Credential {
        id: proved_credential.credential.id,
        created_date: proved_credential.credential.created_date,
        issuance_date: proved_credential.credential.issuance_date,
        last_modified: proved_credential.credential.last_modified,
        deleted_at: proved_credential.credential.deleted_at,
        protocol: proved_credential.credential.protocol,
        redirect_uri: proved_credential.credential.redirect_uri,
        role: proved_credential.credential.role,
        state: proved_credential.credential.state,
        claims: convert_inner_of_inner(proved_credential.credential.claims),
        issuer_identifier: Some(issuer_identifier),
        issuer_certificate,
        holder_identifier: Some(holder_identifier),
        schema: proved_credential
            .credential
            .schema
            .map(|schema| from_provider_schema(schema, organisation.to_owned())),
        interaction: None,
        key: proved_credential.credential.key,
        suspend_end_date: convert_inner(proved_credential.credential.suspend_end_date),
        profile: proved_credential.credential.profile,
        credential_blob_id: proved_credential.credential.credential_blob_id,
        wallet_unit_attestation_blob_id: proved_credential
            .credential
            .wallet_unit_attestation_blob_id,
        wallet_app_attestation_blob_id: proved_credential.credential.wallet_app_attestation_blob_id,
    })
}

fn from_provider_schema(schema: CredentialSchema, organisation: Organisation) -> CredentialSchema {
    CredentialSchema {
        id: schema.id,
        deleted_at: schema.deleted_at,
        created_date: schema.created_date,
        last_modified: schema.last_modified,
        name: schema.name,
        format: schema.format,
        revocation_method: schema.revocation_method,
        key_storage_security: schema.key_storage_security,
        layout_type: schema.layout_type,
        layout_properties: schema.layout_properties,
        imported_source_url: schema.imported_source_url,
        schema_id: schema.schema_id,
        claim_schemas: schema.claim_schemas,
        organisation: organisation.into(),
        allow_suspension: schema.allow_suspension,
        requires_app_attestation: schema.requires_app_attestation,
    }
}

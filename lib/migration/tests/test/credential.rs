use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_credential() {
    let schema = get_schema().await;

    let credential = schema
        .table("credential")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "issuance_date",
            "deleted_at",
            "protocol",
            "credential_schema_id",
            "interaction_id",
            "key_id",
            "role",
            "redirect_uri",
            "state",
            "suspend_end_date",
            "holder_identifier_id",
            "issuer_identifier_id",
            "issuer_certificate_id",
            "profile",
            "credential_blob_id",
            "wallet_unit_attestation_blob_id",
            "wallet_app_attestation_blob_id",
        ])
        .index("index-Credential-CreatedDate", false, &["created_date"])
        .index("index-Credential-Role", false, &["role"])
        .index("index-Credential-DeletedAt", false, &["deleted_at"])
        .index("index-Credential-State", false, &["state"])
        .index(
            "index-Credential-SuspendEndDate",
            false,
            &["suspend_end_date"],
        );
    credential
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    credential
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential
        .column("issuance_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    credential
        .column("deleted_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    credential
        .column("protocol")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential
        .column("credential_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-Credential-CredentialSchemaId",
            "credential_schema",
            "id",
        );
    credential
        .column("interaction_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-Credential-InteractionId", "interaction", "id");
    credential
        .column("key_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-Credential-KeyId", "key", "id");
    credential
        .column("role")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential
        .column("redirect_uri")
        .r#type(ColumnType::String(Some(1000)))
        .nullable(true);
    credential
        .column("state")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential
        .column("suspend_end_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    credential
        .column("holder_identifier_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_credential_holder_identifier", "identifier", "id");
    credential
        .column("issuer_identifier_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_credential_issuer_identifier", "identifier", "id");
    credential
        .column("issuer_certificate_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-credential-issuer_certificate", "certificate", "id");
    credential
        .column("profile")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential
        .column("credential_blob_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_credential_credential_blob_id", "blob_storage", "id");
    credential
        .column("wallet_unit_attestation_blob_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key(
            "fk_credential_wallet_unit_attestation_blob_id",
            "blob_storage",
            "id",
        );
    credential
        .column("wallet_app_attestation_blob_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key(
            "fk_credential_wallet_app_attestation_blob_id",
            "blob_storage",
            "id",
        );
}

#[tokio::test]
async fn test_db_schema_claim() {
    let schema = get_schema().await;

    let claim = schema.table("claim").columns(&[
        "id",
        "created_date",
        "last_modified",
        "claim_schema_id",
        "credential_id",
        "value",
        "path",
        "selectively_disclosable",
    ]);
    claim
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    claim
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    claim
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    claim
        .column("claim_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-Claim-ClaimSchemaId", "claim_schema", "id");
    claim
        .column("credential_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-Claim-CredentialId", "credential", "id");
    claim
        .column("value")
        .r#type(ColumnType::Blob)
        .nullable(true);
    claim
        .column("path")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    claim
        .column("selectively_disclosable")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
}

#[tokio::test]
async fn test_db_schema_validity_credential() {
    let schema = get_schema().await;

    let validity_credential = schema.table("validity_credential").columns(&[
        "id",
        "created_date",
        "credential",
        "credential_id",
        "type",
    ]);
    validity_credential
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    validity_credential
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    validity_credential
        .column("credential")
        .r#type(ColumnType::Blob)
        .nullable(false)
        .default(None);
    validity_credential
        .column("credential_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-Lvvc-CredentialId", "credential", "id");
    validity_credential
        .column("type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

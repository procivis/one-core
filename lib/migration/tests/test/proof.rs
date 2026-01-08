use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_proof() {
    let schema = get_schema().await;

    let proof = schema
        .table("proof")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "redirect_uri",
            "proof_schema_id",
            "transport",
            "interaction_id",
            "verifier_key_id",
            "protocol",
            "state",
            "requested_date",
            "completed_date",
            "role",
            "verifier_identifier_id",
            "verifier_certificate_id",
            "profile",
            "proof_blob_id",
            "engagement",
        ])
        .index("index-Proof-CreatedDate", false, &["created_date"]);
    proof
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    proof
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    proof
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    proof
        .column("redirect_uri")
        .r#type(ColumnType::String(Some(1000)))
        .nullable(true);
    proof
        .column("proof_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-Proof-ProofSchemaId", "proof_schema", "id");
    proof
        .column("transport")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    proof
        .column("interaction_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-Proof-InteractionId", "interaction", "id");
    proof
        .column("verifier_key_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-Proof-VerifierKeyId", "key", "id");
    proof
        .column("protocol")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    proof
        .column("state")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    proof
        .column("requested_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    proof
        .column("completed_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    proof
        .column("role")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    proof
        .column("verifier_identifier_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_proof_verifier_identifier", "identifier", "id");
    proof
        .column("verifier_certificate_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk-proof-verifier_certificate", "certificate", "id");
    proof
        .column("profile")
        .r#type(ColumnType::String(None))
        .nullable(true);
    proof
        .column("proof_blob_id")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key("fk_proof_proof_blob_id", "blob_storage", "id");
    proof
        .column("engagement")
        .r#type(ColumnType::String(None))
        .nullable(true);
}

#[tokio::test]
async fn test_db_schema_proof_claim() {
    let schema = get_schema().await;

    let proof_claim = schema
        .table("proof_claim")
        .columns(&["claim_id", "proof_id"]);
    proof_claim
        .column("claim_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key()
        .foreign_key("fk-ProofClaim-ClaimId", "claim", "id");
    proof_claim
        .column("proof_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key()
        .foreign_key("fk-ProofClaim-ProofId", "proof", "id");
}

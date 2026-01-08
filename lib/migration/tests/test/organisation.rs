use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_organisation() {
    let schema = get_schema().await;

    let organisation = schema
        .table("organisation")
        .columns(&[
            "id",
            "created_date",
            "last_modified",
            "name",
            "deactivated_at",
            "wallet_provider",
            "wallet_provider_issuer",
        ])
        .index("index-Organisation-Name-Unique", true, &["name"])
        .index(
            "index-Organisation-WalletProvider-Unique",
            true,
            &["wallet_provider"],
        );
    organisation
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    organisation
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    organisation
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    organisation
        .column("name")
        .r#type(ColumnType::Text)
        .nullable(false)
        .default(None);
    organisation
        .column("deactivated_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    organisation
        .column("wallet_provider")
        .r#type(ColumnType::String(None))
        .nullable(true);
    organisation
        .column("wallet_provider_issuer")
        .r#type(ColumnType::Uuid)
        .nullable(true)
        .foreign_key(
            "fk-OrganisationWalletUnitIssuer-IssuerId",
            "identifier",
            "id",
        );
}

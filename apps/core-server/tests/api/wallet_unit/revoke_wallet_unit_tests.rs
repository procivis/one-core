use one_core::model::wallet_unit::WalletUnitStatus;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_units::TestWalletUnit;

#[tokio::test]
async fn test_revoke_wallet_unit_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let wallet_unit = context
        .db
        .wallet_units
        .create(
            org,
            TestWalletUnit {
                status: Some(WalletUnitStatus::Active),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.wallet_units.revoke(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let wallet_unit = context
        .db
        .wallet_units
        .get(wallet_unit.id, &Default::default())
        .await
        .unwrap();
    assert_eq!(wallet_unit.status, WalletUnitStatus::Revoked);
}

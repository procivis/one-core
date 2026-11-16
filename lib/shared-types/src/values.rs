//! Opaque string values.

use crate::macros::string_ids;

string_ids! {
    /// Newtype for DPoP nonce values
    DpopNonce,
    /// Represents credential during transport (usually OpenID4VCI <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3-6.1.2.1>)
    SerializedCredential,
    /// Type of a transaction data item of a proof request
    TransactionDataType,
}

use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Display, Formatter};

use one_crypto::encryption::EncryptionError;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumMessage, EnumString, IntoStaticStr};

use crate::model::relation::OptionalRelatedExtError;
use crate::provider::provider_directory::ProviderError;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    IntoStaticStr,
    EnumMessage,
    EnumString,
    Display,
)]
#[allow(non_camel_case_types)]
pub enum ErrorCode {
    #[strum(message = "Unmapped error code")]
    BR_0000,

    #[strum(message = "Credential not found")]
    BR_0001,

    #[strum(message = "Credential state invalid")]
    BR_0002,

    #[strum(message = "Credential: Missing claim")]
    BR_0003,

    #[strum(message = "Missing credentials for provided interaction")]
    BR_0004,

    #[strum(message = "Missing credential data for provided credential")]
    BR_0005,

    #[strum(message = "Credential schema not found")]
    BR_0006,

    #[strum(message = "Credential schema already exists")]
    BR_0007,

    #[strum(message = "Credential schema: Missing claims")]
    BR_0008,

    #[strum(message = "Missing credential schema")]
    BR_0009,

    #[strum(message = "Missing claim schema")]
    BR_0010,

    #[strum(message = "Missing claim schemas")]
    BR_0011,

    #[strum(message = "Proof not found")]
    BR_0012,

    #[strum(message = "Proof state invalid")]
    BR_0013,

    #[strum(message = "Proof schema not found")]
    BR_0014,

    #[strum(message = "Proof schema already exists")]
    BR_0015,

    #[strum(message = "Proof schema: no required claim")]
    BR_0017,

    #[strum(message = "Proof schema: duplicate claim schema")]
    BR_0018,

    #[strum(message = "Proof schema deleted")]
    BR_0019,

    #[strum(message = "Missing proof schema")]
    BR_0020,

    #[strum(message = "Organisation not found")]
    BR_0022,

    #[strum(message = "Organisation already exists")]
    BR_0023,

    #[strum(message = "DID not found")]
    BR_0024,

    #[strum(message = "Invalid DID type")]
    BR_0025,

    #[strum(message = "Invalid DID method")]
    BR_0026,

    #[strum(message = "DID deactivated")]
    BR_0027,

    #[strum(message = "DID value already exists")]
    BR_0028,

    #[strum(message = "DID cannot be deactivated")]
    BR_0029,

    #[strum(message = "DID invalid key number")]
    BR_0030,

    #[strum(message = "Missing DID method")]
    BR_0031,

    #[strum(message = "Credential schema already exists")]
    BR_0032,

    #[strum(message = "Missing interaction for access token")]
    BR_0033,

    #[strum(message = "Revocation list not found")]
    BR_0034,

    #[strum(message = "Key not found")]
    BR_0037,

    #[strum(message = "Missing formatter")]
    BR_0038,

    #[strum(message = "Generic key storage error")]
    BR_0039,

    #[strum(message = "Missing key storage")]
    BR_0040,

    #[strum(message = "Invalid key storage type")]
    BR_0041,

    #[strum(message = "Missing key algorithm")]
    BR_0042,

    #[strum(message = "Invalid key algorithm type")]
    BR_0043,

    #[strum(message = "Missing revocation method")]
    BR_0044,

    #[strum(message = "Missing revocation method for the provided credential status type")]
    BR_0045,

    #[strum(message = "Missing exchange protocol")]
    BR_0046,

    #[strum(message = "Model mapping error")]
    BR_0047,

    #[strum(message = "OpenID4VC error")]
    BR_0048,

    #[strum(message = "Credential status list bitstring handling error")]
    BR_0049,

    #[strum(message = "Crypto provider error")]
    BR_0050,

    #[strum(message = "Configuration validation error")]
    BR_0051,

    #[strum(message = "Invalid exchange type")]
    BR_0052,

    #[strum(message = "Database error")]
    BR_0054,

    #[strum(message = "Formatter provider error")]
    BR_0057,

    #[strum(message = "Provided datatype is invalid or value does not match the expected type")]
    BR_0061,

    #[strum(message = "Exchange protocol provider error")]
    BR_0062,

    #[strum(message = "Key algorithm provider error")]
    BR_0063,

    #[strum(message = "DID method provider error")]
    BR_0064,

    #[strum(message = "DID method is missing key algorithm capability")]
    BR_0065,

    #[strum(message = "Key already exists")]
    BR_0066,

    #[strum(message = "Proof unauthorized")]
    BR_0071,

    #[strum(message = "Key must not be remote")]
    BR_0076,

    #[strum(message = "Verification engagement not enabled")]
    BR_0077,

    #[strum(message = "Sharing not possible with non QR_CODE engagement")]
    BR_0078,

    #[strum(message = "Engagement missing for ISO mDL flow")]
    BR_0079,

    #[strum(message = "Wallet instance must be active")]
    BR_0081,

    #[strum(message = "Invalid DCQL query or presentation definition")]
    BR_0083,

    #[strum(message = "General input validation error")]
    BR_0084,

    #[strum(message = "Invalid handle invitation received")]
    BR_0085,

    #[strum(message = "Incorrect credential schema type")]
    BR_0087,

    #[strum(message = "Missing organisation")]
    BR_0088,

    #[strum(message = "Missing configuration entity")]
    BR_0089,

    #[strum(message = "JSON-LD: BBS key needed")]
    BR_0090,

    #[strum(message = "BBS key not supported")]
    BR_0091,

    #[strum(message = "Missing proof for provided interaction")]
    BR_0094,

    #[strum(message = "Invalid key")]
    BR_0096,

    #[strum(message = "Operation not supported by revocation method")]
    BR_0098,

    #[strum(message = "Credential state is Revoked or Suspended and cannot be shared")]
    BR_0099,

    #[strum(message = "History event not found")]
    BR_0100,

    #[strum(message = "Revocation error")]
    BR_0101,

    #[strum(message = "Missing task")]
    BR_0103,

    #[strum(message = "Missing proof input schemas")]
    BR_0104,

    #[strum(message = "Primary/Secondary attribute does not exists")]
    BR_0105,

    #[strum(message = "Missing nested claims")]
    BR_0106,

    #[strum(message = "Nested claims should be empty")]
    BR_0107,

    #[strum(message = "Slash in claim schema key name")]
    BR_0108,

    #[strum(message = "Missing parent claim schema")]
    BR_0109,

    #[strum(message = "Revocation method not compatible")]
    BR_0110,

    #[strum(message = "Incompatible issuance exchange protocol")]
    BR_0111,

    #[strum(message = "Incompatible proof exchange protocol")]
    BR_0112,

    #[strum(message = "Invalid claim type (mdoc: root level claims must be objects)")]
    BR_0117,

    #[strum(message = "Attribute combination not allowed")]
    BR_0118,

    #[strum(message = "Nested claims in arrays cannot be requested")]
    BR_0125,

    #[strum(message = "Claim schema key exceeded max length (255)")]
    BR_0126,

    #[strum(message = "DID method is not supported for issuance of this credential format")]
    BR_0127,

    #[strum(message = "Unsupported key type for CSR")]
    BR_0128,

    #[strum(message = "Incorrect disclosure level")]
    BR_0130,

    #[strum(message = "Layout properties are not supported")]
    BR_0131,

    #[strum(message = "Credential schema: Duplicit claim schema")]
    BR_0133,

    #[strum(message = "Imported proof schema error")]
    BR_0135,

    #[strum(message = "Missing Schema ID")]
    BR_0138,

    #[strum(message = "Schema ID not allowed")]
    BR_0139,

    #[strum(message = "No default transport specified")]
    BR_0142,

    #[strum(message = "Forbidden claim name")]
    BR_0145,

    #[strum(message = "Schema id not allowed for credential schema")]
    BR_0146,

    #[strum(message = "Invalid mdl request")]
    BR_0147,

    #[strum(message = "Invalid wallet instance attestation nonce")]
    BR_0153,

    #[strum(message = "Key storage not supported for proof request")]
    BR_0158,

    #[strum(message = "Transport combination not allowed for exchange protocol")]
    BR_0159,

    #[strum(message = "No suitable transport protocol found on verifier/holder")]
    BR_0160,

    #[strum(message = "Suspension not supported for revocation method")]
    BR_0162,

    #[strum(message = "Sharing not supported to this proof schema")]
    BR_0163,

    #[strum(message = "Proof schema: claim schemas empty")]
    BR_0164,

    #[strum(message = "Wallet instance must be in pending state")]
    BR_0168,

    #[strum(message = "User Provided incorrect user code")]
    BR_0169,

    #[strum(message = "Invalid Transaction Code Use")]
    BR_0170,

    #[strum(message = "SD-JWT VC type metadata not found")]
    BR_0172,

    #[strum(message = "Proof of possession for issued credential could not be verified")]
    BR_0173,

    #[strum(message = "Invalid create trust anchor request")]
    BR_0177,

    #[strum(message = "Forbidden")]
    BR_0178,

    #[strum(message = "Multiple matching trust anchors")]
    BR_0179,

    #[strum(message = "Invalid update request")]
    BR_0181,

    #[strum(message = "Initialization error")]
    BR_0183,

    #[strum(message = "Not initialized")]
    BR_0184,

    #[strum(message = "Unable to resolve trust entity by did")]
    BR_0185,

    #[strum(message = "No trust entity found for the given did")]
    BR_0186,

    #[strum(message = "JSON deserialization error")]
    BR_0189,

    #[strum(message = "Suspension not enabled for revocation method that only supports suspension")]
    BR_0191,

    #[strum(message = "Redirect uri disabled or scheme not allowed")]
    BR_0192,

    #[strum(message = "Invalid image data")]
    BR_0193,

    #[strum(message = "Empty object not allowed")]
    BR_0194,

    #[strum(message = "Empty elements in array not allowed")]
    BR_0195,

    #[strum(message = "Exchange protocol operation disabled")]
    BR_0196,

    #[strum(message = "Invalid credential role")]
    BR_0197,

    #[strum(message = "Invalid proof role")]
    BR_0198,

    #[strum(message = "Key handle error")]
    BR_0201,

    #[strum(message = "Empty value not allowed")]
    BR_0204,

    #[strum(message = "DID, Key or Certificate must be specified when creating identifier")]
    BR_0206,

    #[strum(message = "Identifier not found")]
    BR_0207,

    #[strum(message = "Certificate signature invalid")]
    BR_0211,

    #[strum(message = "Certificate revoked")]
    BR_0212,

    #[strum(message = "Certificate is expired")]
    BR_0213,

    #[strum(message = "Key does not match public key of certificate")]
    BR_0214,

    #[strum(message = "Invalid holder identifier")]
    BR_0217,

    #[strum(message = "Identifier not compatible with format")]
    BR_0218,

    #[strum(message = "No key with required role available")]
    BR_0222,

    #[strum(message = "Certificate not found")]
    BR_0223,

    #[strum(message = "Certificate parsing failure")]
    BR_0224,

    #[strum(message = "Wallet storage type not supported")]
    BR_0225,

    #[strum(message = "Identifier type disabled")]
    BR_0227,

    #[strum(message = "Only didId or identifierId must be present when creating trust entity")]
    BR_0228,

    #[strum(
        message = "Type mandatory when identifierId or content is used for creating trust entity"
    )]
    BR_0229,

    #[strum(message = "Content attribute not editable for DID trust entity type")]
    BR_0230,

    #[strum(message = "Subject key identifier not matching")]
    BR_0231,

    #[strum(message = "CRL check failure")]
    BR_0233,

    #[strum(message = "CRL is expired")]
    BR_0234,

    #[strum(message = "CRL signature invalid")]
    BR_0235,

    #[strum(message = "Duplicate trust entity")]
    BR_0236,

    #[strum(message = "Rejection not supported")]
    BR_0237,

    #[strum(message = "MSO refresh not possible")]
    BR_0238,

    #[strum(message = "Identifier already exists")]
    BR_0240,

    #[strum(message = "Organisation is deactivated")]
    BR_0241,

    #[strum(message = "Certificate must be specified for identifiers of type certificate")]
    BR_0242,

    #[strum(message = "Certificate is missing authority key identifier")]
    BR_0243,

    #[strum(message = "Invalid CA trust entity certificate chain")]
    BR_0244,

    #[strum(message = "Unsupported claim data type")]
    BR_0245,

    #[strum(message = "Presentation submission must contain at least one credential")]
    BR_0246,

    #[strum(message = "Certificate already exists")]
    BR_0247,

    #[strum(message = "Unknown critical X.509 extension")]
    BR_0248,

    #[strum(message = "Certificate key usage violation")]
    BR_0249,

    #[strum(message = "Basic constraints violation")]
    BR_0250,

    #[strum(message = "Blob storage provider not found")]
    BR_0252,

    #[strum(message = "DID cannot be reactivated")]
    BR_0256,

    #[strum(message = "Interaction not found")]
    BR_0257,

    #[strum(message = "Minimum refresh time not reached")]
    BR_0258,

    #[strum(message = "Wallet instance not found")]
    BR_0259,

    #[strum(message = "Wallet instance revoked")]
    BR_0261,

    #[strum(message = "Cannot fetch wallet instance attestation")]
    BR_0264,

    #[strum(message = "Invalid wallet instance state")]
    BR_0265,

    #[strum(message = "App integrity validation failed")]
    BR_0266,

    #[strum(message = "Missing proof")]
    BR_0268,

    #[strum(message = "Missing public key")]
    BR_0269,

    #[strum(
        message = "App integrity check required: proof and public key must only be provided on wallet instance activation"
    )]
    BR_0270,

    #[strum(message = "Wallet instance already exists")]
    BR_0271,

    #[strum(message = "Engagement provided for non ISO mDL flow")]
    BR_0272,

    #[strum(message = "NFC adapter not enabled")]
    BR_0273,

    #[strum(message = "NFC not supported")]
    BR_0274,

    #[strum(message = "Another NFC operation running")]
    BR_0275,

    #[strum(message = "NFC operation not running")]
    BR_0276,

    #[strum(message = "NFC operation cancelled")]
    BR_0277,

    #[strum(message = "NFC session closed")]
    BR_0278,

    #[strum(message = "App integrity check not required: provide proof and public key")]
    BR_0279,

    #[strum(message = "App integrity check required")]
    BR_0280,

    #[strum(message = "App integrity check not required")]
    BR_0281,

    #[strum(message = "Wallet provider already associated")]
    BR_0283,

    #[strum(message = "Wallet provider not configured")]
    BR_0284,

    #[strum(message = "Identifier does not belong to this organisation")]
    BR_0285,

    #[strum(message = "Wallet provider not associated with any organisation")]
    BR_0286,

    #[strum(message = "Organisation not specified")]
    BR_0290,

    #[strum(message = "Invalid presentation submission")]
    BR_0291,

    #[strum(message = "Verification protocol is incompatible with this endpoint version")]
    BR_0292,

    #[strum(message = "Invalid wallet provider Url")]
    BR_0295,

    #[strum(message = "Holder wallet instance not found")]
    BR_0296,

    #[strum(message = "Insufficient security level")]
    BR_0297,

    #[strum(message = "Proof schema: Invalid credential combination")]
    BR_0305,

    #[strum(message = "Key storage security level not supported")]
    BR_0309,

    #[strum(message = "Key storage does not fulfill required security levels")]
    BR_0310,

    #[strum(message = "Duplicate proof input credential schema")]
    BR_0313,

    #[strum(message = "Invalid history source")]
    BR_0315,

    #[strum(message = "Service validation error")]
    BR_0323,

    #[strum(message = "Invalid signature validity boundary")]
    BR_0324,

    #[strum(message = "Missing signer provider")]
    BR_0326,

    #[strum(message = "Invalid signature id")]
    BR_0327,

    #[strum(message = "Incompatible referenced provider")]
    BR_0328,

    #[strum(message = "Signing error")]
    BR_0329,

    #[strum(message = "Invalid key selection")]
    BR_0330,

    #[strum(message = "Chain or content must be specified when creating Certificate")]
    BR_0331,

    #[strum(message = "Invalid signature payload")]
    BR_0332,

    #[strum(message = "Key signature issuer not supported")]
    BR_0336,

    #[strum(message = "Transaction code not supported")]
    BR_0337,

    #[strum(message = "Invalid transaction code length")]
    BR_0338,

    #[strum(message = "Invalid transaction code description length")]
    BR_0346,

    #[strum(message = "Remote HTTP request failed")]
    BR_0347,

    #[strum(message = "HTTP request failure")]
    BR_0348,

    #[strum(message = "MQTT failure")]
    BR_0349,

    #[strum(message = "BLE adapter not enabled")]
    BR_0350,

    #[strum(message = "BLE not supported")]
    BR_0351,

    #[strum(message = "BLE permission declined")]
    BR_0352,

    #[strum(message = "BLE failure")]
    BR_0353,

    #[strum(message = "Cache failure")]
    BR_0354,

    #[strum(message = "JWT handling failure")]
    BR_0355,

    #[strum(message = "DB entry already exists")]
    BR_0357,

    #[strum(message = "Bearer token expired")]
    BR_0358,

    #[strum(message = "Certificate not yet valid")]
    BR_0359,

    #[strum(message = "OAuth failure")]
    BR_0360,

    #[strum(message = "Key storage operation not supported")]
    BR_0361,

    #[strum(message = "DID resolution failed")]
    BR_0363,

    #[strum(message = "Invalid DID value")]
    BR_0364,

    #[strum(message = "DID operation not supported")]
    BR_0365,

    #[strum(message = "Invalid credential state transition")]
    BR_0366,

    #[strum(message = "Encryption Error")]
    BR_0368,

    #[strum(message = "Disallowed notification URL host")]
    BR_0369,

    #[strum(message = "Forbidden notification URL scheme")]
    BR_0370,

    #[strum(message = "Invalid notification URL")]
    BR_0371,

    #[strum(message = "Notifications not allowed")]
    BR_0372,

    #[strum(message = "Notification not found")]
    BR_0377,

    #[strum(message = "Verifier provider not found")]
    BR_0380,

    #[strum(message = "Invalid signer")]
    BR_0381,

    #[strum(message = "Invalid trust list identifier")]
    BR_0382,

    #[strum(message = "Trust list publication not found")]
    BR_0383,

    #[strum(message = "Trust list publisher internal error")]
    BR_0384,

    #[strum(message = "Invalid trust list params")]
    BR_0385,

    #[strum(message = "Unsupported trust list role")]
    BR_0386,

    #[strum(message = "Trust entry not found")]
    BR_0387,

    #[strum(message = "Missing trust list publisher")]
    BR_0388,

    #[strum(message = "Unsupported trust list key type")]
    BR_0389,

    #[strum(message = "Trust entry doesn't belong to specified trust list")]
    BR_0390,

    #[strum(message = "Trust collection not found")]
    BR_0391,

    #[strum(message = "Trust list role was not provided and is not specified by resolved list")]
    BR_0392,

    #[strum(message = "Invalid LoTE content")]
    BR_0393,

    #[strum(message = "Ambiguous trust resolution, identifier has multiple active certificates")]
    BR_0394,

    #[strum(message = "Remote HTTP request status failure (4xx)")]
    BR_0395,

    #[strum(message = "Unsupported identifier type")]
    BR_0396,

    #[strum(message = "Failed to encode public key")]
    BR_0397,

    #[strum(message = "Trust collection already exists")]
    BR_0398,

    #[strum(message = "Invalid trust list subscription reference")]
    BR_0399,

    #[strum(message = "Trust list subscriber provider not found")]
    BR_0400,

    #[strum(message = "Local trust collection cannot be synced")]
    BR_0401,

    #[strum(message = "Trust list subscription not found")]
    BR_0402,

    #[strum(message = "Trust list subscription already exists")]
    BR_0403,

    #[strum(message = "Invalid task params")]
    BR_0405,

    #[strum(message = "Verifier instance not found")]
    BR_0406,

    #[strum(message = "Trust collections out of sync")]
    BR_0407,

    #[strum(
        message = "Certificates on the same identifier must not be duplicates and must not have the same name and expiry"
    )]
    BR_0408,

    #[strum(message = "Certificate roles must not be empty")]
    BR_0409,

    #[strum(message = "Certificate not trusted")]
    BR_0410,

    #[strum(message = "Operation not allowed by registration certificate")]
    BR_0411,

    #[strum(message = "Invalid filter value: credential schema not found")]
    BR_0413,

    #[strum(message = "Invalid filter value: proof schema not found")]
    BR_0414,

    #[strum(message = "Missing trust information blob")]
    BR_0415,

    #[strum(message = "Invalid trust information")]
    BR_0416,

    #[strum(message = "Certificate role not allowed")]
    BR_0418,

    #[strum(message = "Multi-level inheritance not allowed")]
    BR_0419,

    #[strum(message = "Unsupported Accept content type")]
    BR_0425,

    #[strum(message = "History entry missing metadata")]
    BR_0426,

    #[strum(message = "History entry has invalid metadata type")]
    BR_0427,

    #[strum(message = "Missing provider dependency")]
    BR_0428,

    #[strum(message = "Invalid provider params")]
    BR_0429,

    #[strum(message = "Missing provider")]
    BR_0430,

    #[strum(message = "Provider is disabled")]
    BR_0431,

    #[strum(message = "Unsupported key algorithm")]
    BR_0432,

    #[strum(message = "Interaction not allowed - untrusted")]
    BR_0433,

    #[strum(message = "Credential schema batch size must be at least 2")]
    BR_0434,

    #[strum(message = "Credential schema must specify at least one format")]
    BR_0435,

    #[strum(message = "Credential schema mapping format not part of formats")]
    BR_0437,

    #[strum(message = "Credential schema mapping namespace missing")]
    BR_0438,

    #[strum(message = "Credential schema duplicate formats")]
    BR_0439,

    #[strum(message = "Credential schema duplicate mapping formats")]
    BR_0440,

    #[strum(message = "Invalid credential type")]
    BR_0442,

    #[strum(message = "No unused, active credentials left in credential batch")]
    BR_0443,

    #[strum(message = "Invalid document for signing")]
    BR_0444,

    #[strum(message = "Document signer not found")]
    BR_0445,

    #[strum(message = "User ID token not expected")]
    BR_0446,

    #[strum(message = "Missing user ID token")]
    BR_0447,

    #[strum(message = "Invalid user ID token")]
    BR_0448,

    #[strum(message = "User authentication not configured for wallet provider")]
    BR_0449,

    #[strum(message = "Wallet unit is not in pending state")]
    BR_0450,

    #[strum(message = "Missing wallet unit attestation")]
    BR_0451,

    #[strum(message = "Refresh not supported for this credential")]
    BR_0452,

    #[strum(message = "User authentication not required")]
    BR_0453,

    #[strum(message = "User authentication required")]
    BR_0454,

    #[strum(message = "Wallet unit registration expired, restart registration")]
    BR_0455,

    #[strum(message = "CSC API client error")]
    BR_0456,

    #[strum(message = "Trust list subscription role is required but missing")]
    BR_0457,

    #[strum(message = "Invalid or unsupported transaction data")]
    BR_0458,

    #[strum(message = "Invalid transaction data assignment")]
    BR_0459,

    #[strum(message = "Credential schema format does not support transaction data")]
    BR_0460,

    #[strum(
        message = "Transaction data references a credential schema not part of the proof schema"
    )]
    BR_0461,

    #[strum(message = "Transaction data not found")]
    BR_0462,

    #[strum(
        message = "Transaction data entries cannot each be authorized by a distinct credential"
    )]
    BR_0463,

    #[strum(message = "Verifier instance registration not yet supported")]
    BR_0464,

    #[strum(message = "Verifier provider is already associated to another organisation")]
    BR_0465,

    #[strum(message = "Invalid instance role")]
    BR_0467,

    #[strum(message = "Access certificate provisioning disabled")]
    BR_0468,

    #[strum(message = "Missing user access token")]
    BR_0469,

    #[strum(message = "Verifier provider not configured")]
    BR_0470,

    #[strum(message = "Verifier provider not associated with any organisation")]
    BR_0471,

    #[strum(message = "Trust collections must all belong to the same provider")]
    BR_0472,

    #[strum(message = "User authentication mandated but not supported for instances with OS WEB")]
    BR_0473,

    #[strum(message = "Credential schema expiration must be greater than 0")]
    BR_0474,

    #[strum(message = "Ecosystem not permitted by organisation config")]
    BR_0475,

    #[strum(message = "Usage of ecosystem enforced, none provided/matching")]
    BR_0476,

    #[strum(message = "Ecosystem validation failure")]
    BR_0477,

    #[strum(message = "No suitable provider")]
    BR_0478,

    #[strum(message = "Invalid query")]
    BR_0479,

    #[strum(message = "Deprecated fields must not be mixed with their replacements")]
    BR_0480,

    #[strum(message = "Ecosystem enforcement mandated by provider, cannot be disabled")]
    BR_0481,

    #[strum(message = "Invalid format selection")]
    BR_0482,

    #[strum(
        message = "Credential already issued, refresh is only supported for mdoc and batch credentials"
    )]
    BR_0483,

    #[strum(message = "Missing logo blob")]
    BR_0484,

    #[strum(message = "Invalid claim path")]
    BR_0485,

    #[strum(message = "Access certificate provider not on trust list")]
    BR_0486,

    #[strum(message = "Access certificate is not valid")]
    BR_0487,

    #[strum(message = "Issuer not on trust list for the issued credential type")]
    BR_0488,

    #[strum(message = "Registration certificate provider not on trust list")]
    BR_0489,

    #[strum(message = "Trust attestation does not cover the issued credential")]
    BR_0490,

    #[strum(
        message = "Access certificate does not match the registration certificate or registry response"
    )]
    BR_0491,

    #[strum(message = "Registration certificate is not valid")]
    BR_0492,

    #[strum(message = "National registry signer not on trust list")]
    BR_0493,

    #[strum(message = "Wallet Instance Attestation issuer not on wallet provider trust list")]
    BR_0494,

    #[strum(message = "Wallet Instance Attestation is malformed")]
    BR_0495,

    #[strum(message = "Key Attestation issuer not on wallet provider trust list")]
    BR_0496,

    #[strum(message = "Key Attestation is malformed")]
    BR_0497,

    #[strum(message = "Wallet Instance Attestation and Key Attestation issuers do not match")]
    BR_0498,

    #[strum(message = "Key Attestation is revoked")]
    BR_0499,

    #[strum(message = "Key storage security level is not attested")]
    BR_0500,

    #[strum(message = "Required entitlements missing from trust attestation")]
    BR_0501,

    #[strum(message = "CRL is not yet valid")]
    BR_0502,

    #[strum(message = "Requested credential is not permitted by the verifier's trust attestation")]
    BR_0503,

    #[strum(message = "Wallet attestation lifetime must be greater than 0")]
    BR_0504,

    #[strum(message = "Wallet Instance Attestation is revoked")]
    BR_0505,
}

/// Extra detail some errors carry into the response body, next to their error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorData {
    EcosystemsResolved(crate::model::ecosystem::EcosystemOutcomes),
}

pub trait ErrorCodeMixin: Error + Send + Sync + 'static {
    fn error_code(&self) -> ErrorCode;

    /// Defaults to none. Override it only when the caller can act on the detail.
    fn error_data(&self) -> Option<ErrorData> {
        None
    }
}

impl ErrorCodeMixin for Infallible {
    fn error_code(&self) -> ErrorCode {
        match *self {}
    }
}

pub trait ErrorCodeMixinExt: ErrorCodeMixin {
    fn error_while(self, context: impl Display) -> NestedError;
}

impl<T: ErrorCodeMixin> ErrorCodeMixinExt for T {
    fn error_while(self, context: impl Display) -> NestedError {
        NestedError {
            context: Some(context.to_string()),
            source: Box::new(self),
        }
    }
}

#[derive(Debug)]
pub struct NestedError {
    context: Option<String>,
    source: Box<dyn ErrorCodeMixin>,
}

impl Error for NestedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.source)
    }
}

impl ErrorCodeMixin for NestedError {
    fn error_code(&self) -> ErrorCode {
        self.source.error_code()
    }

    // nesting adds context, it does not drop what the nested error carries
    fn error_data(&self) -> Option<ErrorData> {
        self.source.error_data()
    }
}

impl Display for NestedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(context) = &self.context {
            writeln!(f, "Error while {context}.")?;
            write!(f, "Caused by: {}", self.source)?;
        } else {
            write!(f, "{}", self.source)?;
        }
        Ok(())
    }
}

pub trait ContextWithErrorCode<T, E: ErrorCodeMixin> {
    /// Nests the error with the given context.
    ///
    /// The context, when displayed, should fit the following pattern:
    ///
    /// "Error while `context`.<br>
    /// Caused by: `nested error`"
    fn error_while(self, context: impl Display) -> Result<T, NestedError>;
}

impl<T, E: ErrorCodeMixin> ContextWithErrorCode<T, E> for Result<T, E> {
    fn error_while(self, context: impl Display) -> Result<T, NestedError> {
        self.map_err(|e| NestedError {
            context: Some(context.to_string()),
            source: Box::new(e),
        })
    }
}

// ProviderError already describes the context, no need for nesting
impl From<ProviderError> for NestedError {
    fn from(error: ProviderError) -> Self {
        Self {
            context: None,
            source: Box::new(error),
        }
    }
}

// OptionalRelatedExtError already describes the context, no need for nesting
impl From<OptionalRelatedExtError> for NestedError {
    fn from(error: OptionalRelatedExtError) -> Self {
        Self {
            context: None,
            source: Box::new(error),
        }
    }
}

impl ErrorCodeMixin for EncryptionError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0062
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use thiserror::Error;

    use super::*;

    #[test]
    fn test_error_display() {
        #[derive(Debug, Error)]
        enum TestError {
            #[error("Leaf")]
            Leaf,

            #[error(transparent)]
            Nested(#[from] NestedError),
        }

        impl ErrorCodeMixin for TestError {
            fn error_code(&self) -> ErrorCode {
                match self {
                    Self::Leaf => ErrorCode::BR_0000,
                    Self::Nested(nested) => nested.error_code(),
                }
            }
        }

        let leaf_error = TestError::Leaf;
        assert_eq!(leaf_error.to_string(), "Leaf");

        let once_nested_error = leaf_error.error_while("nesting 1");
        assert_eq!(
            once_nested_error.to_string(),
            "Error while nesting 1.\nCaused by: Leaf"
        );

        let twice_nested_error = once_nested_error.error_while("nesting 2");
        assert_eq!(
            twice_nested_error.to_string(),
            "Error while nesting 2.\nCaused by: Error while nesting 1.\nCaused by: Leaf"
        );
    }
}

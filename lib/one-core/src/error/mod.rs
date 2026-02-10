use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use strum::{Display, EnumMessage, IntoStaticStr};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, IntoStaticStr, EnumMessage, Display,
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

    #[strum(message = "Missing revocation list for provided DID")]
    BR_0035,

    #[strum(message = "Missing credential index on revocation list")]
    BR_0036,

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

    #[strum(message = "Unsupported key type")]
    BR_0053,

    #[strum(message = "Database error")]
    BR_0054,

    #[strum(message = "Invalid formatter type")]
    BR_0056,

    #[strum(message = "Formatter provider error")]
    BR_0057,

    #[strum(message = "Crypto provider error")]
    BR_0058,

    #[strum(message = "Missing signer")]
    BR_0059,

    #[strum(message = "Missing signer algorithm")]
    BR_0060,

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

    #[strum(message = "Wallet unit must be active")]
    BR_0081,

    #[strum(message = "Invalid DCQL query or presentation definition")]
    BR_0083,

    #[strum(message = "General input validation error")]
    BR_0084,

    #[strum(message = "Invalid handle invitation received")]
    BR_0085,

    #[strum(message = "Cannot fetch credential offer or presentation definition")]
    BR_0086,

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

    #[strum(message = "Credential already revoked")]
    BR_0092,

    #[strum(message = "Missing proof for provided interaction")]
    BR_0094,

    #[strum(message = "StatusList2021 not supported for credential issuance and revocation")]
    BR_0095,

    #[strum(message = "Invalid key")]
    BR_0096,

    #[strum(message = "Requested wallet storage type cannot be fulfilled")]
    BR_0097,

    #[strum(message = "Revocation method does not support state (REVOKE, SUSPEND)")]
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

    #[strum(message = "Trust anchor name already in use")]
    BR_0113,

    #[strum(message = "Trust anchor type not found")]
    BR_0114,

    #[strum(message = "Trust anchor not found")]
    BR_0115,

    #[strum(message = "Invalid claim type (mdoc: root level claims must be objects)")]
    BR_0117,

    #[strum(message = "Attribute combination not allowed")]
    BR_0118,

    #[strum(message = "Trust entity not found")]
    BR_0121,

    #[strum(message = "Trust anchor type is not Simple Trust List")]
    BR_0122,

    #[strum(message = "trustAnchorId and entityId are already present")]
    BR_0120,

    #[strum(message = "Trust anchor must be publish")]
    BR_0123,

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

    #[strum(message = "Trust management provider not found")]
    BR_0132,

    #[strum(message = "Credential schema: Duplicit claim schema")]
    BR_0133,

    #[strum(message = "Imported proof schema error")]
    BR_0135,

    #[strum(message = "Missing Schema ID")]
    BR_0138,

    #[strum(message = "Schema ID not allowed")]
    BR_0139,

    #[strum(message = "Validity constraint must be specified for LVVC revocation method")]
    BR_0140,

    #[strum(message = "No default transport specified")]
    BR_0142,

    #[strum(message = "Invalid SCAN_TO_VERIFY parameters")]
    BR_0144,

    #[strum(message = "Forbidden claim name")]
    BR_0145,

    #[strum(message = "Schema id not allowed for credential schema")]
    BR_0146,

    #[strum(message = "Invalid mdl request")]
    BR_0147,

    #[strum(message = "Invalid wallet unit attestation nonce")]
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

    #[strum(message = "Validity constraint out of range")]
    BR_0166,

    #[strum(message = "Wallet unit must be in pending")]
    BR_0168,

    #[strum(message = "User Provided incorrect user code")]
    BR_0169,

    #[strum(message = "Invalid Transaction Code Use")]
    BR_0170,

    #[strum(message = "SD-JWT VC type metadata not found")]
    BR_0172,

    #[strum(
        message = "Proof of possession of issuer did for issued credential could not be verified"
    )]
    BR_0173,

    #[strum(message = "Invalid create trust anchor request")]
    BR_0177,

    #[strum(message = "Forbidden")]
    BR_0178,

    #[strum(message = "Multiple matching trust anchors")]
    BR_0179,

    #[strum(message = "Trust entity has duplicates")]
    BR_0180,

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

    #[strum(message = "Trust anchor is disabled")]
    BR_0187,

    #[strum(message = "Trust anchor must be client")]
    BR_0188,

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

    #[strum(message = "Credential role must be Holder for revocation check")]
    BR_0197,

    #[strum(message = "Invalid proof role")]
    BR_0198,

    #[strum(message = "Invalid exchange type for retract proof")]
    BR_0199,

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

    #[strum(message = "Certificate is expired or not yet valid")]
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

    #[strum(message = "CRL outdated")]
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

    #[strum(message = "Blob storage error")]
    BR_0251,

    #[strum(message = "Blob storage provider not found")]
    BR_0252,

    #[strum(message = "DID cannot be reactivated")]
    BR_0256,

    #[strum(message = "Interaction not found")]
    BR_0257,

    #[strum(message = "Minimum refresh time not reached")]
    BR_0258,

    #[strum(message = "Wallet unit not found")]
    BR_0259,

    #[strum(message = "Wallet provider not enabled in config")]
    BR_0260,

    #[strum(message = "Wallet unit revoked")]
    BR_0261,

    #[strum(message = "No wallet unit registration")]
    BR_0262,

    #[strum(message = "Cannot fetch wallet unit attestation")]
    BR_0264,

    #[strum(message = "Invalid wallet unit state")]
    BR_0265,

    #[strum(message = "App integrity validation failed")]
    BR_0266,

    #[strum(message = "Missing proof")]
    BR_0268,

    #[strum(message = "Missing public key")]
    BR_0269,

    #[strum(
        message = "App integrity check required: proof and public key must only be provided on wallet unit activation"
    )]
    BR_0270,

    #[strum(message = "Wallet unit already exists")]
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

    #[strum(message = "Holder wallet unit not found")]
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

    #[strum(
        message = "Chain or self-signed must be specified when creating Certificate Authority identifier"
    )]
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
}

pub trait ErrorCodeMixin: Error + Send + Sync + 'static {
    fn error_code(&self) -> ErrorCode;
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
            context: context.to_string(),
            source: Box::new(self),
        }
    }
}

#[derive(Debug)]
pub struct NestedError {
    pub context: String,
    pub source: Box<dyn ErrorCodeMixin>,
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
}

impl Display for NestedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Error while {}.", self.context)?;
        writeln!(f, "Caused by: {}", self.source)?;
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
            context: context.to_string(),
            source: Box::new(e),
        })
    }
}

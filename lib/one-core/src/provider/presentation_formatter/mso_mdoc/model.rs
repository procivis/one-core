use ciborium::cbor;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize, Serializer, ser};
use serde_with::skip_serializing_none;

use super::session_transcript::SessionTranscript;
use crate::proto::cose::CoseSign1;
use crate::provider::credential_formatter::mdoc_formatter::util::{
    DataElementIdentifier, DataElementValue, EmbeddedCbor, IssuerSigned, MDLVersion, Namespace,
};
use crate::provider::verification_protocol::iso_mdl::common::ItemsRequest;

pub type DeviceSignedItems = IndexMap<DataElementIdentifier, DataElementValue>;
pub type DeviceNamespaces = IndexMap<Namespace, DeviceSignedItems>;

pub type DocType = String;
pub type ErrorCode = i64;
pub type DocumentError = IndexMap<DocType, ErrorCode>;
pub type Errors = IndexMap<Namespace, ErrorItems>;
pub type ErrorItems = IndexMap<DataElementIdentifier, ErrorCode>;

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub version: MDLVersion<1, 0>,
    pub documents: Option<Vec<Document>>,
    pub document_errors: Option<Vec<DocumentError>>,
    pub status: u64,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub doc_type: DocType,
    pub issuer_signed: IssuerSigned,
    pub device_signed: DeviceSigned,
    pub errors: Option<Errors>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    pub name_spaces: EmbeddedCbor<DeviceNamespaces>,
    pub device_auth: DeviceAuth,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuth {
    pub device_signature: Option<CoseSign1>,
}

// used in DeviceSigned as detached payload
// should be serialized as cbor array: DeviceAuthentication = ["DeviceAuthentication", SessionTranscriptBytes, DocType; DeviceNameSpaceBytes]
#[derive(Debug, PartialEq)]
pub(crate) struct DeviceAuthentication {
    pub session_transcript: SessionTranscript,
    pub doctype: DocType,
    pub device_namespaces: EmbeddedCbor<DeviceNamespaces>,
}

impl Serialize for DeviceAuthentication {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([
            "DeviceAuthentication",
            self.session_transcript,
            self.doctype,
            self.device_namespaces,
        ])
        .map_err(ser::Error::custom)?
        .serialize(serializer)
    }
}

// used in ReaderAuth as detached payload
// should be serialized as cbor array: ReaderAuthentication = ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]
#[derive(Debug)]
pub(crate) struct ReaderAuthentication {
    pub session_transcript: SessionTranscript,
    pub items_request: EmbeddedCbor<ItemsRequest>,
}

impl Serialize for ReaderAuthentication {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([
            "ReaderAuthentication",
            self.session_transcript,
            self.items_request,
        ])
        .map_err(ser::Error::custom)?
        .serialize(serializer)
    }
}

pub mod dcapi {
    use ciborium::cbor;
    use serde::{Deserialize, Serialize, Serializer, de, ser};

    use crate::provider::credential_formatter::mdoc_formatter::util::Bstr;
    use crate::provider::verification_protocol::iso_mdl::common::EphemeralSessionKey;

    /// ISO 18013-7, C.2
    #[derive(Debug, Clone)]
    pub(crate) struct EncryptionInfo {
        pub parameters: EncryptionParameters,
    }

    impl<'a> Deserialize<'a> for EncryptionInfo {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'a>,
        {
            let (fixed_id, parameters): (String, EncryptionParameters) =
                ciborium::Value::deserialize(deserializer)?
                    .deserialized()
                    .map_err(de::Error::custom)?;

            if fixed_id != "dcapi" {
                return Err(de::Error::custom(format!("Invalid identifier: {fixed_id}")));
            }

            Ok(Self { parameters })
        }
    }

    /// ISO 18013-7, C.2
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct EncryptionParameters {
        #[allow(unused)]
        pub nonce: Bstr,
        pub recipient_public_key: EphemeralSessionKey,
    }

    /// ISO 18013-7, C.3
    #[derive(Debug, Clone)]
    pub(crate) struct EncryptedResponse {
        pub data: EncryptedResponseData,
    }

    impl Serialize for EncryptedResponse {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            cbor!(["dcapi", self.data])
                .map_err(ser::Error::custom)?
                .serialize(serializer)
        }
    }

    /// ISO 18013-7, C.3
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct EncryptedResponseData {
        pub enc: Bstr,
        pub cipher_text: Bstr,
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use similar_asserts::assert_eq;

    use super::dcapi::EncryptionInfo;
    use crate::mapper::decode_cbor_base64url;

    #[test]
    fn test_deserialize_encryption_info() {
        // generated on iOS
        let encryption_info: EncryptionInfo = decode_cbor_base64url(
            "gmVkY2FwaaJlbm9uY2VQlr86NxTOo8Noo4xBjiq9-XJyZWNpcGllbnRQdWJsaWNLZXmkAQIgASFYIG5u3GlvW9A2YYt-oDDfE0-0U7MxV4XsTddaeTctU8RVIlggzNIK0vTwM-emWPK_aMPn5BA5QZvlIYpM6vqgu13tmg4",
        ).unwrap();

        assert_eq!(
            encryption_info.parameters.nonce.0,
            hex!("96bf3a3714cea3c368a38c418e2abdf9")
        );
        assert_eq!(
            encryption_info
                .parameters
                .recipient_public_key
                .to_p256_sec1()
                .unwrap(),
            hex!(
                "046e6edc696f5bd036618b7ea030df134fb453b3315785ec4dd75a79372d53c455ccd20ad2f4f033e7a658f2bf68c3e7e41039419be5218a4ceafaa0bb5ded9a0e"
            )
        );
    }
}

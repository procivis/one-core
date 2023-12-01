use std::str::FromStr;

use did_key::Document;
use shared_types::DidValue;

use crate::provider::did_method::{
    dto::{DidDocumentDTO, DidVerificationMethodDTO, PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO},
    DidMethodError,
};

pub(super) fn convert_document(doc: Document) -> Result<DidDocumentDTO, DidMethodError> {
    let methods = doc
        .verification_method
        .into_iter()
        .filter_map(|method| {
            let pub_key = method.public_key?;

            let public_key_jwk: PublicKeyJwkDTO = if let did_key::KeyFormat::JWK(data) = pub_key {
                match data.key_type.as_str() {
                    "EC" => PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
                        crv: data.curve,
                        x: data.x?,
                        y: data.y,
                    }),
                    "OKP" => PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
                        crv: data.curve,
                        x: data.x?,
                        y: data.y,
                    }),
                    _ => return None,
                }
            } else {
                return None;
            };

            Some(DidVerificationMethodDTO {
                id: method.id,
                r#type: method.key_type,
                controller: method.controller,
                public_key_jwk,
            })
        })
        .collect();

    let id = DidValue::from_str(&doc.id).map_err(|_| DidMethodError::NotSupported)?;

    Ok(DidDocumentDTO {
        context: vec![doc.context],
        id,
        verification_method: methods,
        authentication: doc.authentication,
        assertion_method: doc.assertion_method,
        key_agreement: doc.key_agreement,
        capability_invocation: doc.capability_invocation,
        capability_delegation: doc.capability_delegation,
    })
}

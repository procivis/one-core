use std::collections::HashMap;
use std::str::FromStr;

use json_ld::{IriBuf, Loader, RemoteDocument};

pub fn vc_permanent_resident_card() -> json_syntax::Value {
    json_syntax::Value::from_str(include_str!("vc_permanent_resident_card.jsonld")).unwrap()
}

pub fn context_vc2_0() -> json_syntax::Value {
    json_syntax::Value::from_str(include_str!("context_vc2_0.jsonld")).unwrap()
}

pub fn context_citizenship() -> json_syntax::Value {
    json_syntax::Value::from_str(include_str!("context_citizenship.jsonld")).unwrap()
}

pub fn document_loader() -> impl Loader {
    [
        (
            IriBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
            RemoteDocument::new(None, None, context_vc2_0()),
        ),
        (
            IriBuf::from_str("https://w3id.org/citizenship/v4rc1").unwrap(),
            RemoteDocument::new(None, None, context_citizenship()),
        ),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>()
}

pub fn vc_windsurf_race_committee() -> json_syntax::Value {
    json_syntax::Value::from_str(include_str!("vc_windsurf_race_committee.jsonld")).unwrap()
}

pub fn context_examples_vocabulary() -> json_syntax::Value {
    json_syntax::Value::from_str(
        r#"{
            "@context": {
                "@vocab": "https://www.w3.org/ns/credentials/examples#"
            }
        }"#,
    )
    .unwrap()
}

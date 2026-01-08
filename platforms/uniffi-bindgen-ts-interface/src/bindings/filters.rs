// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

use askama::Result;
use heck::{ToLowerCamelCase, ToPascalCase, ToShoutySnakeCase};
use uniffi_bindgen::interface::{AsType, Type};

/// Workaround types that need to be treated differently
fn type_exception(type_name: &str) -> Option<String> {
    match type_name {
        "OptionalString" => Some("string | null /* pass null to clear the value */".to_string()),
        _ => None,
    }
}

pub fn hidden_type(typ: &impl AsType, _: &dyn askama::Values) -> Result<bool> {
    let r#type = typ.as_type();
    if let Some(name) = r#type.name() {
        return Ok(type_exception(name).is_some());
    }
    Ok(false)
}

pub fn typescript_type_name(
    typ: &impl AsType,
    askama_values: &dyn askama::Values,
) -> Result<String> {
    Ok(match typ.as_type() {
        Type::Int8 => "number /*i8*/".into(),
        Type::Int16 => "number /*i16*/".into(),
        Type::Int32 => "number /*i32*/".into(),
        Type::Int64 => "number /*i64*/".into(), // possible overflow
        Type::UInt8 => "number /*u8*/".into(),
        Type::UInt16 => "number /*u16*/".into(),
        Type::UInt32 => "number /*u32*/".into(),
        Type::UInt64 => "number /*u64*/".into(), // possible overflow
        Type::Float32 => "number /*f32*/".into(),
        Type::Float64 => "number /*f64*/".into(), // possible overflow
        Type::Boolean => "boolean".into(),
        Type::String => "string".into(),
        Type::Bytes => "number[] /*bytearray*/".into(),
        Type::Timestamp => "Date".into(),
        Type::Duration => "number /* in milliseconds */".into(),
        Type::Enum { name, .. }
        | Type::Record { name, .. }
        | Type::Object { name, .. }
        | Type::Custom { name, .. } => {
            type_exception(&name).unwrap_or(typescript_class_name(&name, askama_values)?)
        }
        Type::CallbackInterface { name, .. } => name.to_lower_camel_case(),
        Type::Optional { inner_type } => {
            format!(
                "{} | undefined",
                typescript_type_name(&inner_type, askama_values)?
            )
        }
        Type::Sequence { inner_type } => format!(
            "Array<{}>",
            typescript_type_name(&inner_type, askama_values)?
        ),
        Type::Map {
            key_type,
            value_type,
        } => format!(
            "Record<{}, {}>",
            typescript_type_name(&key_type, askama_values)?,
            typescript_type_name(&value_type, askama_values)?,
        ),
    })
}

pub fn typescript_fn_name(raw_name: &str, _: &dyn askama::Values) -> Result<String> {
    Ok(raw_name.to_lower_camel_case())
}

pub fn typescript_var_name(raw_name: &str, _: &dyn askama::Values) -> Result<String> {
    Ok(raw_name.to_lower_camel_case())
}

pub fn typescript_enum_variant_name(raw_name: &str, _: &dyn askama::Values) -> Result<String> {
    Ok(raw_name.to_shouty_snake_case())
}

pub fn typescript_class_name(raw_name: &str, _: &dyn askama::Values) -> Result<String> {
    Ok(raw_name.to_pascal_case())
}

pub fn typescript_docstring(s: &str, _: &dyn askama::Values, level: &i32) -> Result<String> {
    let comment = if s.contains('\n') {
        let contents = textwrap::indent(&textwrap::dedent(s), " * ");
        format!("/**\n{contents}\n */")
    } else {
        format!("/** {s} */")
    };
    Ok(textwrap::indent(&comment, &" ".repeat(*level as usize)))
}

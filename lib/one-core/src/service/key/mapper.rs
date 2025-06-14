use one_dto_mapper::convert_inner;
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType};
use shared_types::KeyId;
use time::OffsetDateTime;
use yasna::models::ObjectIdentifier;

use super::dto::{GetKeyListResponseDTO, KeyGenerateCSRRequestProfile};
use crate::model::key::{GetKeyList, Key};
use crate::model::organisation::Organisation;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::service::error::ServiceError;
use crate::service::key::dto::{KeyGenerateCSRRequestDTO, KeyRequestDTO, KeyResponseDTO};

pub(super) fn from_create_request(
    key_id: KeyId,
    request: KeyRequestDTO,
    organisation: Organisation,
    generated_key: StorageGeneratedKey,
) -> Key {
    let now = OffsetDateTime::now_utc();

    Key {
        id: key_id,
        created_date: now,
        last_modified: now,
        public_key: generated_key.public_key,
        name: request.name.to_owned(),
        key_reference: generated_key.key_reference,
        storage_type: request.storage_type.to_owned(),
        key_type: request.key_type,
        organisation: Some(organisation),
    }
}

impl TryFrom<Key> for KeyResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Key) -> Result<Self, Self::Error> {
        let organisation_id = value
            .organisation
            .ok_or(ServiceError::MappingError(
                "organisation is None".to_string(),
            ))?
            .id;

        Ok(Self {
            id: value.id.into(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            organisation_id,
            name: value.name,
            public_key: value.public_key,
            key_type: value.key_type,
            storage_type: value.storage_type,
        })
    }
}

impl From<GetKeyList> for GetKeyListResponseDTO {
    fn from(value: GetKeyList) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub(super) fn request_to_certificate_params(
    request: KeyGenerateCSRRequestDTO,
) -> CertificateParams {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    if let Some(common_name) = request.subject.common_name {
        dn.push(DnType::CommonName, common_name);
    }
    if let Some(country_name) = request.subject.country_name {
        dn.push(DnType::CountryName, country_name);
    }
    if let Some(organisation_name) = request.subject.organisation_name {
        dn.push(DnType::OrganizationName, organisation_name);
    }
    if let Some(state_or_province_name) = request.subject.state_or_province_name {
        dn.push(DnType::StateOrProvinceName, state_or_province_name);
    }
    if let Some(locality_name) = request.subject.locality_name {
        dn.push(DnType::LocalityName, locality_name);
    }
    if let Some(serial_number) = request.subject.serial_number {
        let dn_type_serial_number = vec![2, 5, 4, 5];
        dn.push(DnType::CustomDnType(dn_type_serial_number), serial_number);
    }

    params.distinguished_name = dn;

    if matches!(request.profile, KeyGenerateCSRRequestProfile::Mdl) {
        params.custom_extensions.push(prepare_key_usage_extension());
        params
            .custom_extensions
            .push(prepare_extended_key_usage_extension());
    }

    params
}

fn prepare_key_usage_extension() -> CustomExtension {
    const OID_KEY_USAGE: [u64; 4] = [2, 5, 29, 15];
    const KEY_USAGE_PURPOSE_DIGITAL_SIGNATURE: [u8; 2] = [0x80, 0];
    const BITS_TO_WRITE: usize = 15;

    let content = yasna::construct_der(|writer| {
        writer.write_bitvec_bytes(&KEY_USAGE_PURPOSE_DIGITAL_SIGNATURE, BITS_TO_WRITE);
    });

    CustomExtension::from_oid_content(&OID_KEY_USAGE, content)
}

fn prepare_extended_key_usage_extension() -> CustomExtension {
    const OID_EXTENDED_KEY_USAGE: [u64; 4] = [2, 5, 29, 37];
    const OID_EXTENDED_KEY_USAGE_MDL_DS: [u64; 6] = [1, 0, 18013, 5, 1, 2];

    let mdlds_extended_key_usage = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&ObjectIdentifier::from_slice(
                &OID_EXTENDED_KEY_USAGE_MDL_DS,
            ));
        });
    });
    let mut extended_key_usage_extension =
        CustomExtension::from_oid_content(&OID_EXTENDED_KEY_USAGE, mdlds_extended_key_usage);
    extended_key_usage_extension.set_criticality(true);
    extended_key_usage_extension
}

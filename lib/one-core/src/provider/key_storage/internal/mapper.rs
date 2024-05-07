use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType};
use yasna::models::ObjectIdentifier;

use crate::provider::key_storage::dto::{GenerateCSRRequestDTO, GenerateCSRRequestProfile};

pub(super) fn request_to_certificate_params(request: GenerateCSRRequestDTO) -> CertificateParams {
    let mut params = CertificateParams::default();

    params.not_before = request.not_before;
    params.not_after = request.expires_at;

    let mut dn = DistinguishedName::new();

    dn.push(DnType::CommonName, request.subject.common_name);
    dn.push(DnType::CountryName, request.subject.country_name);

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

    if request.profile == GenerateCSRRequestProfile::Mdl {
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

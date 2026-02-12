use std::collections::{BTreeMap, HashSet};
use std::ops::Add;

use coset::{KeyType, Label, RegisteredLabelWithPrivate};
use hex_literal::hex;
use maplit::{hashmap, hashset};
use serde_json::json;
use shared_types::OrganisationId;
use similar_asserts::assert_eq;
use time::macros::datetime;
use uuid::Uuid;

use super::*;
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::credential_schema::{BackgroundProperties, LayoutProperties, LayoutType};
use crate::model::did::Did;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::provider::credential_formatter::model::{
    CertificateDetails, CredentialSchemaMetadata, Issuer, MockSignatureProvider, MockTokenVerifier,
    PublishedClaimValue,
};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::provider::data_type::error::DataTypeProviderError;
use crate::provider::data_type::model::JsonOrCbor;
use crate::provider::data_type::provider::MockDataTypeProvider;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::presentation_formatter::mso_mdoc::model::DeviceResponse;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::iso_18013_7::OID4VPDraftHandover;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::test_utilities::{dummy_did, dummy_identifier, generic_config, get_dummy_date};

#[test]
fn test_issuer_auth_serialize_deserialize() {
    // taken from spec: D.5.2  Issuer data authentication => IssuerAuth CBOR data
    let issuer_auth_cbor_data = hex!(
           "8443a10126a118215901f3308201ef30820195a00302010202143c4416eed784f3b413e48f56f075abfa6d87e
            b84300a06082a8648ce3d04030230233114301206035504030c0b75746f7069612069616361310b3009060355
            040613025553301e170d3230313030313030303030305a170d3231313030313030303030305a302131123010
            06035504030c0975746f706961206473310b30090603550406130255533059301306072a8648ce3d020106082
            a8648ce3d03010703420004ace7ab7340e5d9648c5a72a9a6f56745c7aad436a03a43efea77b5fa7b88f0197d
            57d8983e1b37d3a539f4d588365e38cbbf5b94d68c547b5bc8731dcd2f146ba381a83081a5301e0603551d120
            417301581136578616d706c65406578616d706c652e636f6d301c0603551d1f041530133011a00fa00d820b65
            78616d706c652e636f6d301d0603551d0e0416041414e29017a6c35621ffc7a686b7b72db06cd12351301f0603
            551d2304183016801454fa2383a04c28e0d930792261c80c4881d2c00b300e0603551d0f0101ff040403020780
            30150603551d250101ff040b3009060728818c5d050102300a06082a8648ce3d04030203480030450221009771
            7ab9016740c8d7bcdaa494a62c053bbdecce1383c1aca72ad08dbc04cbb202203bad859c13a63c6d1ad67d814d
            43e2425caf90d422422c04a8ee0304c0d3a68d5903a2d81859039da66776657273696f6e63312e306f64696765
            7374416c676f726974686d675348412d3235366c76616c756544696765737473a2716f72672e69736f2e313830
            31332e352e31ad00582075167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf015820
            67e539d6139ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed45710258203394372ddb78053f36d5
            d869780e61eda313d44a392092ad8e0527a2fbfe55ae0358202e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e
            41ac52dac9ce86b8613db555045820ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac
            2d59055820fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d0658207d83e507ae
            77db815de4d803b88555d0511d894c897439f5774056416a1c7533075820f0549a145f1cf75cbeeffa881d4857d
            d438d627cf32174b1731c4c38e12ca936085820b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7
            312377e068f660958200b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c0a5820c
            98a170cf36e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c8810b5820b57dd036782f7b14c6a30
            faaaae6ccd5054ce88bdfa51a016ba75eda1edea9480c5820651f8736b18480fe252a03224ea087b5d10ca5485
            146c67c74ac4ec3112d4c3a746f72672e69736f2e31383031332e352e312e5553a4005820d80b83d25173c484c
            5640610ff1a31c949c1d934bf4cf7f18d5223b15dd4f21c0158204d80e1e2e4fb246d97895427ce7000bb59bb24
            c8cd003ecf94bf35bbd2917e340258208b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98
            c2f544035820c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a876d646576696365
            4b6579496e666fa1696465766963654b6579a40102200121582096313d6c63e24e3372742bfdb1a33ba2c897dc
            d68ab8c753e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03
            a2c3d667646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e66
            6fa3667369676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc0743230
            32302d31302d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a
            33303a30325a584059e64205df1e2f708dd6db0847aed79fc7c0201d80fa55badcaf2e1bcf5902e1e5a62e4832
            044b890ad85aa53f129134775d733754d7cb7a413766aeff13cb2e"
        );

    let issuer_auth: CoseSign1 = ciborium::from_reader(&issuer_auth_cbor_data[..]).unwrap();
    let payload = issuer_auth.0.payload.unwrap();

    let mso: EmbeddedCbor<MobileSecurityObject> = ciborium::from_reader(&payload[..]).unwrap();

    let mut payload = vec![];
    ciborium::into_writer(&mso, &mut payload).unwrap();

    let mso1: EmbeddedCbor<MobileSecurityObject> = ciborium::from_reader(&payload[..]).unwrap();

    assert_eq!(mso, mso1);
}

#[test]
fn test_device_response_serialize_deserialize() {
    // from ISO IEC 18013-5_2021: D.4.1.2
    let response_bytes = hex!(
        "
    a36776657273696f6e63312e3069646f63756d656e747381a367646f6354797065756f72672e69736f2e313
    83031332e352e312e6d444c6c6973737565725369676e6564a26a6e616d65537061636573a1716f72672e69
    736f2e31383031332e352e3186d8185863a4686469676573744944006672616e646f6d58208798645b20ea
    200e19ffabac92624bee6aec63aceedecfb1b80077d22bfc20e971656c656d656e744964656e74696669657
    26b66616d696c795f6e616d656c656c656d656e7456616c756563446f65d818586ca468646967657374494
    4036672616e646f6d5820b23f627e8999c706df0c0a4ed98ad74af988af619b4bb078b89058553f44615d7
    1656c656d656e744964656e7469666965726a69737375655f646174656c656c656d656e7456616c7565d90
    3ec6a323031392d31302d3230d818586da4686469676573744944046672616e646f6d5820c7ffa307e5de92
    1e67ba5878094787e8807ac8e7b5b3932d2ce80f00f3e9abaf71656c656d656e744964656e746966696572
    6b6578706972795f646174656c656c656d656e7456616c7565d903ec6a323032342d31302d3230d818586d
    a4686469676573744944076672616e646f6d582026052a42e5880557a806c1459af3fb7eb505d378156632
    9d0b604b845b5f9e6871656c656d656e744964656e7469666965726f646f63756d656e745f6e756d626572
    6c656c656d656e7456616c756569313233343536373839d818590471a4686469676573744944086672616e
    646f6d5820d094dad764a2eb9deb5210e9d899643efbd1d069cc311d3295516ca0b024412d71656c656d65
    6e744964656e74696669657268706f7274726169746c656c656d656e7456616c7565590412ffd8ffe000104a
    46494600010101009000900000ffdb004300130d0e110e0c13110f11151413171d301f1d1a1a1d3a2a2c233
    0453d4947443d43414c566d5d4c51685241435f82606871757b7c7b4a5c869085778f6d787b76ffdb004301
    1415151d191d381f1f38764f434f7676767676767676767676767676767676767676767676767676767676
    76767676767676767676767676767 6767676767676ffc00011080018006403012200021101031101ffc4001
    b00000301000301000000000000000000000005060401020307ffc400321000010303030205020309000000000
    000010203040005110612211331141551617122410781a1163542527391b2c1f1ffc40015010101000000000
    00000000000000000000001ffc4001a110101010003010000000000000000000000014111213161ffda000c03010
    002110311003f00a5bbde22da2329c7d692bc7d0d03f52cfb0ff75e7a7ef3e7709723a1d0dae146ddfbb3c039ce
    07ad2bd47a7e32dbb8dd1d52d6ef4b284f64a480067dfb51f87ffb95ff00eb9ff14d215de66af089ce44b7dbde9cb
    6890a2838eddf18078f7add62d411ef4db9b10a65d6b95a147381ea0d495b933275fe6bba75c114104a8ba4104
    13e983dff004f5af5d34b4b4cde632d0bf1fd1592bdd91c6411f3934c2fa6af6b54975d106dcf4a65ae56e85600
    1ebc03c7ce29dd9eef1ef10fc447dc9da76ad2aee93537a1ba7e4f70dd8eff0057c6dffb5e1a19854a83758e5452
    8750946ec6704850cd037bceb08b6d7d2cc76d3317fc7b5cc04fb6707269c5c6e0c5b60ae549242123b0e493f6
    02a075559e359970d98db89525456b51c951c8afa13ea8e98e3c596836783d5c63f5a61a99fdb7290875db4be8
    8ab384bbbbbfc7183fdeaa633e8951db7da396dc48524fb1a8bd611a5aa2a2432f30ab420a7a6d3240c718cf03
    1fa9ef4c9ad550205aa02951df4a1d6c8421b015b769db8c9229837ea2be8b1b0d39d0eba9c51484efdb8c0efd
    8d258daf3c449699f2edbd4584e7af9c64e3f96b9beb28d4ac40931e6478c8e76a24a825449501d867d2b1dcde
    bae99b9c752ae4ecd6dde4a179c1c1e460938f9149ef655e515c03919a289cb3dca278fb7bf177f4faa829dd8c
    e3f2ac9a7ecde490971fafd7dce15eed9b71c018c64fa514514b24e8e4f8c5c9b75c1e82579dc1233dfec08238
    f6add62d391acc1c5256a79e706d52d431c7a0145140b9fd149eb3a60dc5e88cbbc2da092411e9dc71f39a7766
    b447b344e847dcac9dcb5abba8d145061d43a6fcf1e65cf15d0e90231d3dd9cfe62995c6dcc5ca12a2c904a15f
    71dd27d451453e09d1a21450961cbb3ea8a956433b781f1ce33dfed54f0e2b50a2b71d84ed6db18028a28175f7
    4fc6bda105c529a791c25c4f3c7a11f71586268f4a66b726e33de9ea6f1b52b181c760724e47b514520a5a28a2
    83ffd9d81858ffa4686469676573744944096672616e646f6d58204599f81beaa2b20bd0ffcc9aa03a6f985befab3
    f6beaffa41e6354cdb2ab2ce471656c656d656e744964656e7469666965727264726976696e675f70726976696c
    656765736c656c656d656e7456616c756582a37576656869636c655f63617465676f72795f636f646561416a69
    737375655f64617465d903ec6a323031382d30382d30396b6578706972795f64617465d903ec6a323032342d31
    302d3230a37576656869636c655f63617465676f72795f636f646561426a69737375655f64617465d903ec6a32
    3031372d30322d32336b6578706972795f64617465d903ec6a323032342d31302d32306a697373756572417574
    688443a10126a118215901f3308201ef30820195a00302010202143c4416eed784f3b413e48f56f075abfa6d87
    eb84300a06082a8648ce3d04030230233114301206035504030c0b75746f7069612069616361310b3009060355
    040613025553301e170d3230313030313030303030305a170d3231313030313030303030305a30213112301006
    035504030c0975746f706961206473310b30090603550406130255533059301306072a8648ce3d020106082a86
    48ce3d03010703420004ace7ab7340e5d9648c5a72a9a6f56745c7aad436a03a43efea77b5fa7b88f0197d57d8
    983e1b37d3a539f4d588365e38cbbf5b94d68c547b5bc8731dcd2f146ba381a83081a5301e0603551d12041730
    1581136578616d706c65406578616d706c652e636f6d301c0603551d1f041530133011a00fa00d820b6578616d
    706c652e636f6d301d0603551d0e0416041414e29017a6c35621ffc7a686b7b72db06cd12351301f0603551d230
    4183016801454fa2383a04c28e0d930792261c80c4881d2c00b300e0603551d0f0101ff04040302078030150603
    551d250101ff040b3009060728818c5d050102300a06082a8648ce3d040302034800304502210097717ab901674
    0c8d7bcdaa494a62c053bbdecce1383c1aca72ad08dbc04cbb202203bad859c13a63c6d1ad67d814d43e2425ca
    f90d422422c04a8ee0304c0d3a68d5903a2d81859039da66776657273696f6e63312e306f646967657374416c6
    76f726974686d675348412d3235366c76616c756544696765737473a2716f72672e69736f2e31383031332e352
    e31ad00582075167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf01582067e539d61
    39ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed45710258203394372ddb78053f36d5d869780e6
    1eda313d44a392092ad8e0527a2fbfe55ae0358202e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e41ac52dac
    9ce86b8613db555045820ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac2d5905582
    0fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d0658207d83e507ae77db815de
    4d803b88555d0511d894c897439f5774056416a1c7533075820f0549a145f1cf75cbeeffa881d4857dd438d627c
    f32174b1731c4c38e12ca936085820b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7312377e06
    8f660958200b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c0a5820c98a170cf3
    6e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c8810b5820b57dd036782f7b14c6a30faaaae6cc
    d5054ce88bdfa51a016ba75eda1edea9480c5820651f8736b18480fe252a03224ea087b5d10ca5485146c67c74
    ac4ec3112d4c3a746f72672e69736f2e31383031332e352e312e5553a4005820d80b83d25173c484c5640610ff1
    a31c949c1d934bf4cf7f18d5223b15dd4f21c0158204d80e1e2e4fb246d97895427ce7000bb59bb24c8cd003ec
    f94bf35bbd2917e340258208b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98c2f544035
    820c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a876d6465766963654b6579496
    e666fa1696465766963654b6579a40102200121582096313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c75
    3e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d6676
    46f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa366736
    9676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc074323032302d313
    02d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a33303a303
    25a584059e64205df1e2f708dd6db0847aed79fc7c0201d80fa55badcaf2e1bcf5902e1e5a62e4832044b890ad
    85aa53f129134775d733754d7cb7a413766aeff13cb2e6c6465766963655369676e6564a26a6e616d6553706163
    6573d81841a06a64657669636541757468a1696465766963654d61638443a10105a0f65820e99521a85ad7891b
    806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d6673746174757300
"
    );

    let response: DeviceResponse = ciborium::from_reader(&response_bytes[..]).unwrap();

    let mut s = vec![];
    ciborium::into_writer(&response, &mut s).unwrap();

    let device_response2: DeviceResponse = ciborium::from_reader(&s[..]).unwrap();

    assert_eq!(response, device_response2);
}

#[tokio::test]
async fn test_oid4vp_draft_handover_compute() {
    // ISO 18013-7_2025: B.6.9
    let expected_handover_bytes = hex!(
        "835820DA25C527E5FB75BC2DD31267C02237C4462BA0C1BF37071F692E7DD93B10AD0B5820F6ED8E3220D3C59A5F17EB45F48AB70AEECF9EE21744B1014982350BD96AC0C572616263646566676831323334353637383930"
    );

    let handover = OID4VPDraftHandover::compute(
        "example.com",
        "https://example.com/12345/response",
        "abcdefgh1234567890",
        "1234567890abcdefgh",
    )
    .unwrap();

    let mut s = vec![];
    ciborium::into_writer(&handover, &mut s).unwrap();

    assert_eq!(s, expected_handover_bytes);
}

#[tokio::test]
async fn test_credential_formatting_ok_for_ecdsa() {
    let issuer_did = Issuer::Url("did:key:test".parse().unwrap());

    let claims = vec![PublishedClaim {
        key: "a/b/c".to_string(),
        value: PublishedClaimValue::String("15".to_string()),
        datatype: Some("STRING".to_string()),
        array_item: false,
    }];

    let vcdm = VcdmCredential::new_v2(
        issuer_did.clone(),
        VcdmCredentialSubject::new(std::iter::empty::<(String, String)>()).unwrap(),
    )
    .add_credential_schema(CredentialSchema {
        id: "credential-schema-id".to_string(),
        r#type: "Mdoc".to_string(),
        metadata: Some(CredentialSchemaMetadata {
            layout_type: LayoutType::Card,
            layout_properties: LayoutProperties {
                background: Some(BackgroundProperties {
                    color: Some("color".to_string()),
                    image: None,
                }),
                logo: None,
                primary_attribute: None,
                secondary_attribute: None,
                picture_attribute: None,
                code: None,
            },
        }),
    });

    let holder_did: DidValue = "did:holder:123".parse().unwrap();

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did.clone(),
            ..dummy_did()
        }),
        ..dummy_identifier()
    };
    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(holder_identifier),
        holder_key_id: None,
        issuer_certificate: Some(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id: Uuid::new_v4().into(),
            organisation_id: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            expiry_date: OffsetDateTime::now_utc().add(Duration::days(7)),
            name: "test".to_string(),
            chain: r#"-----BEGIN CERTIFICATE-----
MIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIw
YjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2
aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMu
Y29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMC
Q0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNV
BAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMB
BwMiAAJx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ6OCAeswggHnMA4G
A1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBP
oE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdG
MzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbsw
gbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vl
ci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBa
BggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENE
MjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1Ud
EgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0
ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3/AoQxNFem
Fp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s/EI
1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0Lhg==
-----END CERTIFICATE-----
"#
            .to_string(),
            fingerprint: "fingerprint".to_string(),
            state: CertificateState::Active,
            key: None,
        }),
    };

    let mut did_method_provider = MockDidMethodProvider::new();

    did_method_provider
        .expect_resolve()
        .withf({
            let holder_did = holder_did.clone();

            move |did| did == &holder_did
        })
        .returning(|holder_did| {
            Ok(DidDocument {
                context: json!({}),
                id: holder_did.to_owned(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicJwk::Ec(PublicJwkEc {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: None,
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let params = Params {
        mso_expires_in: Duration::seconds(10),
        mso_expected_update_in: Duration::days(10),
        mso_minimum_refresh_time: Duration::seconds(10),
        leeway: 60_u64,
        ecosystem_schema_ids: vec![],
    };

    let config = generic_config().core;

    let formatter = MdocFormatter::new(
        params,
        Arc::new(MockCertificateValidator::new()),
        Arc::new(did_method_provider),
        config.datatype,
        Arc::new(MockDataTypeProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
    );

    let mut auth_fn = MockSignatureProvider::new();
    auth_fn.expect_sign().returning(|msg| Ok(msg.to_vec()));
    auth_fn
        .expect_get_key_algorithm()
        .return_const(Ok(KeyAlgorithmType::Ecdsa));

    let formatted_credential = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await
        .unwrap();

    let formatted_credential =
        Base64UrlSafeNoPadding::decode_to_vec(formatted_credential, None).unwrap();
    let issuer_signed: IssuerSigned = ciborium::from_reader(&formatted_credential[..]).unwrap();

    let namespaces = issuer_signed.name_spaces.unwrap();
    let cose_sign1 = issuer_signed.issuer_auth.0;

    // check namespaces
    assert_eq!(1, namespaces.len());
    assert_eq!(1, namespaces["a"].len());
    let signed_item = &namespaces["a"][0].inner();

    assert_eq!(0, signed_item.digest_id);
    assert_eq!("b", &signed_item.element_identifier);
    assert_eq!(
        Value::Map(vec![(
            Value::Text("c".to_string()),
            Value::Text("15".to_string())
        )]),
        signed_item.element_value
    );

    // check issuer auth

    // check headers
    let alg = RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256);
    assert_eq!(alg, cose_sign1.protected.header.alg.unwrap());

    let x5chain = cose_sign1
        .unprotected
        .rest
        .iter()
        .find_map(|(label, value)| {
            (label == &Label::Int(iana::HeaderParameter::X5Chain.to_i64()))
                .then_some(value.as_bytes().unwrap())
        })
        .unwrap();

    const EXPECTED_CERTIFICATE_VALUE: &str = "MIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNVBAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMBBwMiAAJx38tO0JCdq3ZecMSW6a-BAAzllydQxVOQ-KDjnwLXJ6OCAeswggHnMA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB_wQCMAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbswgbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vlci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBaBggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3_AoQxNFemFp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s_EI1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0Lhg";
    let expected_certificate =
        Base64UrlSafeNoPadding::decode_to_vec(EXPECTED_CERTIFICATE_VALUE, None).unwrap();
    assert_eq!(&expected_certificate, x5chain);

    // check MSO
    let mso: EmbeddedCbor<MobileSecurityObject> =
        ciborium::from_reader(cose_sign1.payload.unwrap().as_slice()).unwrap();

    // check value digests
    assert_eq!(1, mso.inner().value_digests.len());
    assert_eq!(1, mso.inner().value_digests["a"].len());
    assert!(
        mso.inner().value_digests["a"]
            .get(&signed_item.digest_id)
            .is_some()
    );

    // check COSE_Key
    let cose_key = mso.into_inner().device_key_info.device_key.0;

    assert_eq!(KeyType::Assigned(iana::KeyType::EC2), cose_key.kty);

    let params = BTreeMap::from_iter(cose_key.params);
    let curve_label = Label::Int(iana::Ec2KeyParameter::Crv as _);
    assert_eq!(
        iana::EllipticCurve::P_256 as i128,
        params[&curve_label].as_integer().unwrap().into()
    );

    let x_label = Label::Int(iana::Ec2KeyParameter::X as _);
    assert_eq!(b"xabc", params[&x_label].as_bytes().unwrap().as_slice());

    let y_label = Label::Int(iana::Ec2KeyParameter::Y as _);
    assert_eq!(b"yabc", params[&y_label].as_bytes().unwrap().as_slice());
}

#[tokio::test]
async fn test_unverified_credential_extraction() {
    // arrange
    let issuer_did = Issuer::Url("did:key:test".parse().unwrap());

    let holder_did: DidValue = "did:holder:123".parse().unwrap();

    let claims = vec![PublishedClaim {
        key: "a/b/c".to_string(),
        value: PublishedClaimValue::String("15".to_string()),
        datatype: Some("STRING".to_string()),
        array_item: false,
    }];

    let vcdm = VcdmCredential::new_v2(
        issuer_did.clone(),
        VcdmCredentialSubject::new(std::iter::empty::<(String, String)>()).unwrap(),
    )
    .add_credential_schema(CredentialSchema {
        id: "doctype".to_string(),
        r#type: "Mdoc".to_string(),
        metadata: None,
    });

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did.clone(),
            ..dummy_did()
        }),
        ..dummy_identifier()
    };

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(holder_identifier),
        holder_key_id: None,
        issuer_certificate: Some(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id: Uuid::new_v4().into(),
            organisation_id: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            expiry_date: OffsetDateTime::now_utc().add(Duration::days(7)),
            name: "test".to_string(),
            chain: r#"-----BEGIN CERTIFICATE-----
MIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIw
YjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2
aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMu
Y29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMC
Q0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNV
BAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMB
BwMiAAJx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ6OCAeswggHnMA4G
A1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBP
oE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdG
MzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbsw
gbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vl
ci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBa
BggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENE
MjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1Ud
EgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0
ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3/AoQxNFem
Fp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s/EI
1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0Lhg==
-----END CERTIFICATE-----
"#
            .to_string(),
            fingerprint: "fingerprint".to_string(),
            state: CertificateState::Active,
            key: None,
        }),
    };

    let mut did_method_provider = MockDidMethodProvider::new();

    did_method_provider
        .expect_resolve()
        .withf({
            let holder_did = holder_did.clone();

            move |did| did == &holder_did
        })
        .returning(|holder_did| {
            Ok(DidDocument {
                context: json!({}),
                id: holder_did.to_owned(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicJwk::Ec(PublicJwkEc {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: None,
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let params = Params {
        mso_expires_in: Duration::seconds(10),
        mso_expected_update_in: Duration::days(10),
        mso_minimum_refresh_time: Duration::seconds(10),
        leeway: 60_u64,
        ecosystem_schema_ids: vec![],
    };

    let mut certificate_validator = MockCertificateValidator::new();
    let expiry = OffsetDateTime::now_utc() + Duration::days(1);
    certificate_validator
        .expect_parse_pem_chain()
        .once()
        .returning(move |_, _| {
            let mut public_key_handle = MockSignaturePublicKeyHandle::default();
            public_key_handle
                .expect_as_multibase()
                .return_once(|| Ok("abcd".to_string()));
            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "".to_string(),
                    not_before: OffsetDateTime::now_utc() - Duration::days(1),
                    not_after: expiry,
                    issuer: "Some issuer".to_string(),
                    subject: "Some subject".to_string(),
                    fingerprint: "fingerprint".to_string(),
                    extensions: vec![],
                },
                subject_common_name: Some("common name".to_string()),
                subject_key_identifier: None,
                public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    public_key_handle,
                ))),
            })
        });

    let config = generic_config().core;

    let formatter = MdocFormatter::new(
        params,
        Arc::new(certificate_validator),
        Arc::new(did_method_provider),
        config.datatype,
        Arc::new(MockDataTypeProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
    );

    let mut auth_fn = MockSignatureProvider::new();
    auth_fn.expect_sign().returning(|msg| Ok(msg.to_vec()));
    auth_fn
        .expect_get_key_algorithm()
        .return_const(Ok(KeyAlgorithmType::Ecdsa));

    let formatted_credential = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await
        .unwrap();

    // act
    let credential = formatter
        .extract_credentials_unverified(&formatted_credential, None)
        .await
        .unwrap();

    // assert
    assert_eq!(
        IdentifierDetails::Certificate(CertificateDetails {
            chain: r#"-----BEGIN CERTIFICATE-----
MIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIw
YjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2
aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMu
Y29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMC
Q0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNV
BAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMB
BwMiAAJx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ6OCAeswggHnMA4G
A1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBP
oE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdG
MzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbsw
gbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vl
ci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBa
BggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENE
MjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1Ud
EgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0
ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3/AoQxNFem
Fp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s/EI
1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0Lhg==
-----END CERTIFICATE-----
"#
            .to_string(),
            fingerprint: "fingerprint".to_string(),
            expiry,
            subject_common_name: Some("common name".to_string())
        }),
        credential.issuer
    );

    assert_eq!(
        CredentialSchema {
            id: "doctype".to_owned(),
            r#type: "mdoc".to_owned(),
            metadata: None,
        },
        credential.credential_schema.unwrap()
    );

    assert_eq!(
        hashmap! {
            "a".into() => CredentialClaim {
                selectively_disclosable: true,
                metadata: false,
                value: CredentialClaimValue::Object(hashmap! {
                    "b".into() => CredentialClaim {
                        selectively_disclosable: true,
                        metadata: false,
                        value: CredentialClaimValue::Object(hashmap! {
                            "c".into() =>CredentialClaim {
                                selectively_disclosable: false,
                                metadata: false,
                                value: CredentialClaimValue::String("15".into())
                            }
                        })
                    }
                })
            },
            "doctype".into()=> CredentialClaim {
                selectively_disclosable: false,
                metadata: true,
                value: CredentialClaimValue::String("doctype".into())
            }
        },
        credential.claims.claims
    )
}

#[tokio::test]
async fn test_credential_formatting_ok_for_ecdsa_layout_not_transfered() {
    let detailed_credential = format_and_extract_ecdsa().await;
    assert!(
        detailed_credential
            .credential_schema
            .unwrap()
            .metadata
            .is_none()
    );
}

async fn format_and_extract_ecdsa() -> DetailCredential {
    let issuer_did = Issuer::Url("did:key:test".parse().unwrap());

    let holder_did: DidValue = "did:holder:123".parse().unwrap();

    let claims = vec![PublishedClaim {
        key: "a/b/c".to_string(),
        value: PublishedClaimValue::String("15".to_string()),
        datatype: Some("STRING".to_string()),
        array_item: false,
    }];

    let vcdm = VcdmCredential::new_v2(
        issuer_did,
        VcdmCredentialSubject::new(std::iter::empty::<(String, String)>()).unwrap(),
    )
    .add_credential_schema(CredentialSchema {
        id: "credential-schema-id".to_string(),
        r#type: "Mdoc".to_string(),
        metadata: Some(CredentialSchemaMetadata {
            layout_type: LayoutType::Card,
            layout_properties: LayoutProperties {
                background: Some(BackgroundProperties {
                    color: Some("color".to_string()),
                    image: None,
                }),
                logo: None,
                primary_attribute: None,
                secondary_attribute: None,
                picture_attribute: None,
                code: None,
            },
        }),
    });

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did.clone(),
            ..dummy_did()
        }),
        ..dummy_identifier()
    };

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(holder_identifier),
        holder_key_id: None,
        issuer_certificate: Some(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id: Uuid::new_v4().into(),
            organisation_id: Some(Uuid::new_v4().into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            expiry_date: OffsetDateTime::now_utc().add(Duration::minutes(10)),
            name: "test cert".to_string(),
            chain: r#"-----BEGIN CERTIFICATE-----
MIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIw
YjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2
aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMu
Y29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMC
Q0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNV
BAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMB
BwMiAAJx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ6OCAeswggHnMA4G
A1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBP
oE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdG
MzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbsw
gbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vl
ci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBa
BggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENE
MjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1Ud
EgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0
ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3/AoQxNFem
Fp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s/EI
1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0Lhg==
-----END CERTIFICATE-----
"#
            .to_string(),
            fingerprint: "fingerprint".to_string(),
            state: CertificateState::Active,
            key: None,
        }),
    };

    let mut did_method_provider = MockDidMethodProvider::new();

    did_method_provider
        .expect_resolve()
        .withf({
            let holder_did = holder_did.clone();

            move |did| did == &holder_did
        })
        .returning(|holder_did| {
            Ok(DidDocument {
                context: json!({}),
                id: holder_did.to_owned(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicJwk::Ec(PublicJwkEc {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: None,
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

    let params = Params {
        mso_expires_in: Duration::seconds(10),
        mso_expected_update_in: Duration::days(10),
        mso_minimum_refresh_time: Duration::seconds(10),
        leeway: 60_u64,
        ecosystem_schema_ids: vec![],
    };

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .once()
        .returning(|_, _| {
            let mut public_key_handle = MockSignaturePublicKeyHandle::default();
            public_key_handle
                .expect_as_multibase()
                .return_once(|| Ok("abcd".to_string()));
            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "".to_string(),
                    not_before: OffsetDateTime::now_utc() - Duration::days(1),
                    not_after: OffsetDateTime::now_utc() + Duration::days(1),
                    issuer: "Some issuer".to_string(),
                    subject: "Some subject".to_string(),
                    fingerprint: "fingerprint".to_string(),
                    extensions: vec![],
                },
                subject_common_name: Some("common name".to_string()),
                subject_key_identifier: None,
                public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    public_key_handle,
                ))),
            })
        });

    let config = generic_config().core;

    let formatter = MdocFormatter::new(
        params,
        Arc::new(certificate_validator),
        Arc::new(did_method_provider),
        config.datatype,
        Arc::new(MockDataTypeProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
    );

    let mut auth_fn = MockSignatureProvider::new();
    auth_fn.expect_sign().returning(|msg| Ok(msg.to_vec()));
    auth_fn
        .expect_get_key_algorithm()
        .return_const(Ok(KeyAlgorithmType::Ecdsa));

    let formatted_credential = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await
        .unwrap();

    let mut token_verifier = MockTokenVerifier::new();
    token_verifier
        .expect_verify()
        .never()
        .returning(move |_, _, _, _| Ok(()));

    formatter
        .extract_credentials(&formatted_credential, None, Box::new(token_verifier))
        .await
        .unwrap()
}

#[test]
fn test_credential_schema_id() {
    let params = Params {
        mso_expires_in: Duration::seconds(10),
        mso_expected_update_in: Duration::days(10),
        mso_minimum_refresh_time: Duration::seconds(10),
        leeway: 60_u64,
        ecosystem_schema_ids: vec![],
    };
    let formatter = MdocFormatter::new(
        params,
        Arc::new(MockCertificateValidator::new()),
        Arc::new(MockDidMethodProvider::new()),
        generic_config().core.datatype,
        Arc::new(MockDataTypeProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
    );
    let schema_id = "schema_id_name".to_string();
    let request_dto = CreateCredentialSchemaRequestDTO {
        name: "".to_string(),
        format: "".into(),
        revocation_method: None,
        organisation_id: OrganisationId::from(Uuid::new_v4()),
        claims: vec![],
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: Some(schema_id.clone()),
        allow_suspension: None,
        requires_wallet_instance_attestation: false,
        transaction_code: None,
    };

    let result = formatter.credential_schema_id(
        CredentialSchemaId::from(Uuid::new_v4()),
        &request_dto,
        "https://example.com",
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), schema_id)
}

#[tokio::test]
async fn test_parse_credential() {
    const ISSUED_MDOC: &str = "ompuYW1lU3BhY2VzompuYW1lc3BhY2UxgtgYWGSkaGRpZ2VzdElEAGZyYW5kb21YIMWtCKe0UpTNc-Som7lMdasvokELGUYt1G6w_S7OPpy8cWVsZW1lbnRJZGVudGlmaWVyY29iamxlbGVtZW50VmFsdWWhaW5lc3RlZFN0cmFu2BhYWaRoZGlnZXN0SUQBZnJhbmRvbVggaVSHtwEJdYhB_UNz0MvoyMmUIQZoj31cvTLyKRfdUKZxZWxlbWVudElkZW50aWZpZXJjc3RybGVsZW1lbnRWYWx1ZWFzam5hbWVzcGFjZTKB2BhYXqRoZGlnZXN0SUQCZnJhbmRvbVggLaV6XEY6vAQWrmoGLk9k4KwhuXKslxhYGQWUQ4CvRi1xZWxlbWVudElkZW50aWZpZXJjYXJybGVsZW1lbnRWYWx1ZYJiYTFiYTJqaXNzdWVyQXV0aIRDoQEmoRghWQNGMIIDQjCCAuegAwIBAgIUJ1lFCR_rFo-SnmIFQI_2spfZ8U0wCgYIKoZIzj0EAwIwgYwxEjAQBgNVBAMMCWxvY2FsaG9zdDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEPMA0GA1UEBwwGWnVyaWNoMQswCQYDVQQGEwJDSDEiMCAGCSqGSIb3DQEJARYTc3VwcG9ydEBwcm9jaXZpcy5jaDAeFw0yNTA3MjkxMzEzMDBaFw0yNjA3MjkwMDAwMDBaMBExDzANBgNVBAMMBnNkZ2RmaDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJYXmT8MpwCuYqSJ5gCiDhZE_GcW6K_95Yxh5eUi-Mx6TlNSFf0hmG4l8lUc4VBbW-F3aPaJloS-5KxWgrDbmGyjggGfMIIBmzAfBgNVHSMEGDAWgBTt9O0P3c2e__llFNrZnB8VGciUSzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTpNlM0fkAOmVL_cghB0sc1pEKkdTCByAYIKwYBBQUHAQEEgbswgbgwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvMkU4NjI5NzVGRDA5MEUxRjM1QTY3NENFQUE0RTZDNTZFNUI2Nzc0OC9jZXJ0LzBaBggrBgEFBQcwAoZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vaXNzdWVyLzJFODYyOTc1RkQwOTBFMUYzNUE2NzRDRUFBNEU2QzU2RTVCNjc3NDguZGVyMFkGA1UdHwRSMFAwTqBMoEqGSGh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC8yRTg2Mjk3NUZEMDkwRTFGMzVBNjc0Q0VBQTRFNkM1NkU1QjY3NzQ4LzAVBgNVHSUBAf8ECzAJBgcogYxdBQECMA4GA1UdDwEB_wQEAwIHgDAKBggqhkjOPQQDAgNJADBGAiEA1tdLIzHjsFse_1f3G2pB5hlaP0jZJFIWSVMOrq1AL98CIQCviw63vxlUhoWLwG7Y7fxVffGYYRejF_5bO1hI7KH9U1kBydgYWQHEpmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOiam5hbWVzcGFjZTGiAFggQbhGiPKR2NS_inPDZW5z1ccREMUkmN6J6kj-5HJe7i4BWCDeAcugZ1WThbFnW5ksTwT5349mVLOwcr4tS_ooBu_w_2puYW1lc3BhY2UyoQJYIKTvsv_kcCp3YmIJ1YFX66idSdQ62z3LkJ2Xn_q5lgz5bWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggWnxj014us6_1nQAqd_kI_3r4mFJqyJWyMwRNrqDtHNMiWCCh53efzDuA5jGknqv3WG_czqFVUwOHla5v2c8pPxkCG2dkb2NUeXBlcnBhdmVsLjc1NDUuc3RyaW5nc2x2YWxpZGl0eUluZm-kZnNpZ25lZMB0MjAyNS0xMC0xNVQwODo1ODoxM1ppdmFsaWRGcm9twHQyMDI1LTEwLTE1VDA4OjU4OjEzWmp2YWxpZFVudGlswHQyMDI1LTEwLTE4VDA4OjU4OjEzWm5leHBlY3RlZFVwZGF0ZcB0MjAyNS0xMC0xNlQwODo1ODoxM1pYQL1m2H0lKYlNRbxmo4fhtTG7-rwi1NPiggmQQFejt8G6kIJghGsJ0aVbvTgPtogN4z67KWv2xK3IUCWjxR4rNUo";

    let params = Params {
        mso_expires_in: Duration::seconds(10),
        mso_expected_update_in: Duration::days(10),
        mso_minimum_refresh_time: Duration::seconds(10),
        leeway: 60_u64,
        ecosystem_schema_ids: vec![],
    };

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .once()
        .returning(|_, _| {
            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "".to_string(),
                    not_before: OffsetDateTime::now_utc() - Duration::days(1),
                    not_after: OffsetDateTime::now_utc() + Duration::days(1),
                    issuer: "Some issuer".to_string(),
                    subject: "Some subject".to_string(),
                    fingerprint: "fingerprint".to_string(),
                    extensions: vec![],
                },
                subject_common_name: Some("common name".to_string()),
                subject_key_identifier: None,
                public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    MockSignaturePublicKeyHandle::default(),
                ))),
            })
        });

    let mut datatype_provider = MockDataTypeProvider::new();
    datatype_provider
        .expect_extract_cbor_claim()
        .times(5)
        .returning(|value| {
            if matches!(value, Value::Array(_)) {
                return Err(DataTypeProviderError::UnableToExtract(JsonOrCbor::Cbor(
                    value.to_owned(),
                )));
            }

            Ok(ExtractedClaim {
                data_type: "STRING".to_string(),
                value: "value".to_string(),
            })
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_parse_jwk()
        .once()
        .returning(|_| {
            let mut public_key_handle = MockSignaturePublicKeyHandle::new();
            public_key_handle.expect_as_raw().returning(Vec::new);
            Ok(ParsedKey {
                algorithm_type: KeyAlgorithmType::Ecdsa,
                key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    public_key_handle,
                ))),
            })
        });

    let formatter = MdocFormatter::new(
        params,
        Arc::new(certificate_validator),
        Arc::new(MockDidMethodProvider::new()),
        generic_config().core.datatype,
        Arc::new(datatype_provider),
        Arc::new(key_algorithm_provider),
    );
    let mut verify_mock = MockTokenVerifier::new();
    verify_mock.expect_verify().return_once(|_, _, _, _| Ok(()));

    let credential = formatter
        .parse_credential(ISSUED_MDOC, Box::new(verify_mock))
        .await
        .unwrap();

    assert_eq!(credential.role, CredentialRole::Holder);
    assert_eq!(
        credential.issuance_date.unwrap(),
        datetime!(2025-10-15 08:58:13 UTC)
    );
    let claims = credential.claims.unwrap();
    assert_eq!(claims.len(), 9);

    let get_claim_paths = |filter: &dyn Fn(&Claim) -> bool| {
        HashSet::from_iter(
            claims
                .iter()
                .filter(|claim| filter(claim))
                .map(|claim| claim.path.as_str()),
        )
    };

    // intermediary
    assert_eq!(
        get_claim_paths(&|claim| claim.value.is_none()),
        hashset! {
            "namespace1", "namespace1/obj",
            "namespace2", "namespace2/arr"
        }
    );
    // leaf
    assert_eq!(
        get_claim_paths(&|claim| claim.value == Some("value".to_string())),
        hashset! {
            "namespace1/str", "namespace1/obj/nestedStr",
            "namespace2/arr/0", "namespace2/arr/1"
        }
    );
    // doctype meta claim
    let doctype_claim = claims.iter().find(|claim| claim.path == "doctype").unwrap();
    assert_eq!(doctype_claim.value.as_ref().unwrap(), "pavel.7545.strings");
    assert!(doctype_claim.schema.as_ref().unwrap().metadata);

    // check selectively disclosable flags
    assert_eq!(
        get_claim_paths(&|claim| claim.selectively_disclosable),
        hashset! {
            "namespace1", "namespace1/str", "namespace1/obj",
            "namespace2", "namespace2/arr"
        }
    );

    // claim schema ids of siblings must match
    let arr_0_claim = claims
        .iter()
        .find(|claim| claim.path == "namespace2/arr/0")
        .unwrap();
    let arr_1_claim = claims
        .iter()
        .find(|claim| claim.path == "namespace2/arr/1")
        .unwrap();
    assert_eq!(
        arr_0_claim.schema.as_ref().unwrap().id,
        arr_1_claim.schema.as_ref().unwrap().id
    );

    let schema = credential.schema.unwrap();
    assert_eq!(schema.schema_id, "pavel.7545.strings");
    let claim_schemas = schema.claim_schemas.unwrap();
    assert_eq!(claim_schemas.len(), 7);

    let get_claim_schema_keys = |filter: &dyn Fn(&CredentialSchemaClaim) -> bool| {
        HashSet::from_iter(
            claim_schemas
                .iter()
                .filter(|schema| filter(schema))
                .map(|schema| schema.schema.key.as_str()),
        )
    };

    assert_eq!(
        get_claim_schema_keys(&|_| true),
        hashset! {
            "namespace1", "namespace1/str", "namespace1/obj", "namespace1/obj/nestedStr",
            "namespace2", "namespace2/arr",
            "doctype"
        }
    );

    assert_eq!(
        get_claim_schema_keys(&|schema| schema.schema.metadata),
        hashset! { "doctype" }
    );

    assert_eq!(
        get_claim_schema_keys(&|schema| schema.schema.data_type == "OBJECT"),
        hashset! {
            "namespace1", "namespace1/obj",
            "namespace2"
        }
    );

    assert_eq!(
        get_claim_schema_keys(&|schema| schema.schema.data_type == "STRING"),
        hashset! {
            "namespace1/str", "namespace1/obj/nestedStr",
            "namespace2/arr",
            "doctype"
        }
    );

    assert_eq!(
        get_claim_schema_keys(&|schema| schema.schema.array),
        hashset! { "namespace2/arr" }
    );
}

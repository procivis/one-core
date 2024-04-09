use std::collections::BTreeMap;

use coset::{KeyType, Label, RegisteredLabelWithPrivate};
use hex_literal::hex;
use serde_json::json;
use uuid::Uuid;

use crate::provider::credential_formatter::{CredentialSchemaData, MockSignatureProvider};
use crate::provider::did_method::dto::{DidDocumentDTO, DidVerificationMethodDTO};
use crate::provider::did_method::provider::MockDidMethodProvider;

use super::mdoc::*;
use super::*;

#[derive(Debug, Deserialize)]
struct DeviceResponse {
    documents: Vec<Document>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    issuer_signed: IssuerSigned,
}

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

    let issuer_auth: IssuerAuth = ciborium::from_reader(&issuer_auth_cbor_data[..]).unwrap();
    let payload = issuer_auth.0.payload.unwrap();

    let mso: MobileSecurityObjectBytes = ciborium::from_reader(&payload[..]).unwrap();

    let mut payload = vec![];
    ciborium::into_writer(&mso, &mut payload).unwrap();

    let mso1: MobileSecurityObjectBytes = ciborium::from_reader(&payload[..]).unwrap();

    assert_eq!(mso, mso1);
}

#[test]
fn test_issuer_signed_serialize_deserialize() {
    // from spec: D.4.1.2  mdoc response
    let response_bytes = hex!("
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
        806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d6673746174757300");

    let response: DeviceResponse = ciborium::from_reader(&response_bytes[..]).unwrap();
    let issuer_signed = response.documents.into_iter().next().unwrap().issuer_signed;

    let mut s = vec![];
    ciborium::into_writer(&issuer_signed, &mut s).unwrap();

    let issuer_signed2: IssuerSigned = ciborium::from_reader(&s[..]).unwrap();

    assert_eq!(issuer_signed, issuer_signed2);
}

#[tokio::test]
async fn test_credential_formatting_ok_for_es256() {
    let issuer_did: DidValue = "issuer-did".parse().unwrap();

    let credential_data = CredentialData {
        id: Uuid::new_v4().to_string(),
        issuance_date: OffsetDateTime::now_utc(),
        valid_for: time::Duration::seconds(10),
        claims: vec![("a/b/c".to_string(), "15".to_string())],
        issuer_did: issuer_did.clone(),
        status: vec![],
        schema: CredentialSchemaData {
            id: Some("credential-schema-id".to_string()),
            r#type: None,
            context: None,
            name: "credential-schema-name".to_string(),
        },
    };

    let holder_did: DidValue = "holder-did".parse().unwrap();

    let mut did_method_provider = MockDidMethodProvider::new();

    did_method_provider
        .expect_resolve()
        .withf({
            let holder_did = holder_did.clone();

            move |did| did == &holder_did
        })
        .returning(|holder_did| {
            Ok(DidDocumentDTO {
                context: json!({}),
                id: holder_did.to_owned(),
                verification_method: vec![DidVerificationMethodDTO {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
                        r#use: None,
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
                rest: json!({}),
            })
        });

    let params = Params {
        mso_expires_in: time::Duration::seconds(10),
        mso_expected_update_in: time::Duration::days(10),
    };
    let algorithm = "ES256";

    let formatter = MdocFormatter::new(params, Arc::new(did_method_provider));

    let mut auth_fn = MockSignatureProvider::new();
    auth_fn.expect_sign().returning(|msg| Ok(msg.to_vec()));

    let formatted_credential = formatter
        .format_credentials(
            credential_data,
            &holder_did,
            algorithm,
            vec![],
            vec![],
            Box::new(auth_fn),
            None,
            None,
        )
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
    let signed_item = &namespaces["a"][0].0;

    assert_eq!(0, signed_item.digest_id);
    assert_eq!("b/c", &signed_item.element_identifier);
    assert_eq!("15", signed_item.element_value.as_text().unwrap());

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
    assert_eq!(issuer_did.as_str().as_bytes(), x5chain);

    // check MSO
    let MobileSecurityObjectBytes(mso) =
        ciborium::from_reader(cose_sign1.payload.unwrap().as_slice()).unwrap();

    // check value digests
    assert_eq!(1, mso.value_digests.len());
    assert_eq!(1, mso.value_digests["a"].len());
    assert!(mso.value_digests["a"].get(&signed_item.digest_id).is_some());

    // check COSE_Key
    let cose_key = mso.device_key_info.device_key.0;

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

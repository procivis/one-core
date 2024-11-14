use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm;
use josekit::jwe::JweHeader;
use josekit::jwk::Jwk;

use crate::encryption::EncryptionError;
use crate::signer::eddsa::EDDSASigner;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Header {
    pub key_id: String,
    // apu param
    pub agreement_partyuinfo: String,
    // apv param
    pub agreement_partyvinfo: String,
}

pub struct RemoteJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

/// Construct JWE using AES256GCM encryption
pub fn build_jwe(
    payload: &[u8],
    header: Header,
    recipient_jwk: RemoteJwk,
) -> Result<String, EncryptionError> {
    let jwk = convert_jwk(recipient_jwk)?;
    let header = convert_header(header);

    let encrypter = EcdhEsJweAlgorithm::EcdhEs
        .encrypter_from_jwk(&jwk)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

    josekit::jwe::serialize_compact(payload, &header, &encrypter)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))
}

fn convert_header(input: Header) -> JweHeader {
    let mut header = JweHeader::new();
    header.set_key_id(input.key_id);
    header.set_content_encryption("A256GCM".to_string());
    header.set_agreement_partyuinfo(input.agreement_partyuinfo);
    header.set_agreement_partyvinfo(input.agreement_partyvinfo);
    header
}

fn convert_jwk(input: RemoteJwk) -> Result<Jwk, EncryptionError> {
    match input.kty.as_str() {
        "EC" => {
            let mut jwk = Jwk::new("EC");
            jwk.set_curve(input.crv);
            jwk.set_parameter("x", Some(input.x.into()))
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            jwk.set_parameter(
                "y",
                Some(
                    input
                        .y
                        .ok_or(EncryptionError::Crypto("Missing Y parameter".to_string()))?
                        .into(),
                ),
            )
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            Ok(jwk)
        }
        "OKP" => {
            let mut jwk = Jwk::new("OKP");
            jwk.set_curve(input.crv);
            jwk.set_parameter("x", Some(input.x.into()))
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

            if let Some("Ed25519") = jwk.curve() {
                jwk = ed25519_into_x25519(jwk)?;
            }

            Ok(jwk)
        }
        _ => Err(EncryptionError::Crypto(format!(
            "Invalid key type: {}",
            input.kty
        ))),
    }
}

fn ed25519_into_x25519(mut jwk: Jwk) -> Result<Jwk, EncryptionError> {
    if let Some("Ed25519") = jwk.curve() {
        jwk.set_curve("X25519");

        if let Some(x) = jwk.parameter("x").and_then(|x| x.as_str()) {
            let key = Base64UrlSafeNoPadding::decode_to_vec(x, None)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            let key = EDDSASigner::public_key_into_x25519(&key)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            let key = Base64UrlSafeNoPadding::encode_to_string(key.as_slice())
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            jwk.set_parameter("x", Some(key.into()))
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
        }

        if let Some(d) = jwk.parameter("d").and_then(|d| d.as_str()) {
            let key = Base64UrlSafeNoPadding::decode_to_vec(d, None)
                .map(zeroize::Zeroizing::new)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            let key = EDDSASigner::private_key_into_x25519(&key)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            let key = Base64UrlSafeNoPadding::encode_to_string(key.as_slice())
                .map(zeroize::Zeroizing::new)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

            let key =
                serde_json::to_value(key).map_err(|e| EncryptionError::Crypto(e.to_string()))?;

            jwk.set_parameter("d", Some(key))
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
        };
    }

    Ok(jwk)
}

pub fn extract_jwe_header(jwe: &str) -> Result<Header, EncryptionError> {
    let header_b64 = jwe
        .split('.')
        .next()
        .ok_or_else(|| EncryptionError::Crypto("Invalid JWE".to_string()))?;

    let header = Base64UrlSafeNoPadding::decode_to_vec(header_b64, None)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&header).map_err(|e| EncryptionError::Crypto(e.to_string()))?;
    let jwe_header =
        JweHeader::from_map(map).map_err(|e| EncryptionError::Crypto(e.to_string()))?;

    let key_id = jwe_header
        .key_id()
        .ok_or_else(|| EncryptionError::Crypto("JWE header is missing key_id".to_string()))?
        .to_owned();

    let agreement_partyuinfo = jwe_header
        .agreement_partyuinfo()
        .ok_or_else(|| EncryptionError::Crypto("JWE header is missing apu".to_string()))?;
    let agreement_partyuinfo = String::from_utf8(agreement_partyuinfo)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

    let agreement_partyvinfo = jwe_header
        .agreement_partyvinfo()
        .ok_or_else(|| EncryptionError::Crypto("JWE header is missing apu".to_string()))?;
    let agreement_partyvinfo = String::from_utf8(agreement_partyvinfo)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

    Ok(Header {
        key_id,
        agreement_partyuinfo,
        agreement_partyvinfo,
    })
}

pub fn decrypt_jwe_payload(jwe: &str, private_jwk: &str) -> Result<Vec<u8>, EncryptionError> {
    let mut jwk = josekit::jwk::Jwk::from_bytes(private_jwk.as_bytes())
        .map_err(|err| EncryptionError::Crypto(format!("Failed constructing JWK {err}")))?;

    if let Some("Ed25519") = jwk.curve() {
        jwk = ed25519_into_x25519(jwk)?;
    }

    let decrypter = EcdhEsJweAlgorithm::EcdhEs
        .decrypter_from_jwk(&jwk)
        .map_err(|err| {
            EncryptionError::Crypto(format!("Failed constructing EcdhEs decrypter: {err}"))
        })?;

    let (payload, _) = josekit::jwe::deserialize_compact(jwe, &decrypter)
        .map_err(|err| EncryptionError::Crypto(format!("Failed decrypting JWE: {err}")))?;
    Ok(payload)
}

#[cfg(test)]
mod test {
    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

    use super::*;

    const PRIVATE_JWK_EC: &str = r#"{"kty":"EC","crv":"P-256","x":"KRJIXU-pyEcHURRRQ54jTh9PTTmBYog57rQD1uCsvwo","y":"d31DZcRSqaxAUGBt70HB7uCZdufA6uKdL6BvAzUhbJU","d":"81vofgUlDnb6OUF-WPhH8p1T_mo_F2H9XZvaTvtEZHk"}"#;
    const PRIVATE_JWK_ED25519: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"0yErlKcMCx5DG6zmgoUnnFvLBEQuuYWQSYILwV2O9TM","d":"IM92LwWowNDr7OHXEYwuZ1uVm71ihELJda3i50doJ53TISuUpwwLHkMbrOaChSecW8sERC65hZBJggvBXY71Mw"}"#;

    #[test]
    fn test_decrypt_jwe_ec() {
        let expected_payload = "eyJhdWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9vaWRjLXZlcmlmaWVyL3YxL3Jlc3BvbnNlIiwiZXhwIjoxNzMxNTA5NDY5LCJ2cF90b2tlbiI6Im8yZDJaWEp6YVc5dVl6RXVNR2xrYjJOMWJXVnVkSE9CbzJka2IyTlVlWEJsZFc5eVp5NXBjMjh1TVRnd01UTXVOUzR4TG0xRVRHeHBjM04xWlhKVGFXZHVaV1NpYW01aGJXVlRjR0ZqWlhPaFpIUmxjM1NCMkJoWVg2Um9aR2xuWlhOMFNVUUFabkpoYm1SdmJWZ2dBQnBqa1h3Q2RYdVJUdUlaU3RqWnRCZ0dhZ3FqcFlpeGMxSWFINUpRY1JweFpXeGxiV1Z1ZEVsa1pXNTBhV1pwWlhKbWRtRnNkV1V4YkdWc1pXMWxiblJXWVd4MVpXUjBaWE4wYW1semMzVmxja0YxZEdpRVE2RUJKcUVZSVZrRGx6Q0NBNU13Z2dNNG9BTUNBUUlDRkVQamdGUExNb1NmRk4xSVRPeDc0OUlKWWFtQ01Bb0dDQ3FHU000OUJBTUNNR0l4Q3pBSkJnTlZCQVlUQWtOSU1ROHdEUVlEVlFRSERBWmFkWEpwWTJneEVUQVBCZ05WQkFvTUNGQnliMk5wZG1sek1SRXdEd1lEVlFRTERBaFFjbTlqYVhacGN6RWNNQm9HQTFVRUF3d1RZMkV1WkdWMkxtMWtiQzF3YkhWekxtTnZiVEFlRncweU5ERXhNVE14TkRBMU1EQmFGdzB5TlRBeU1URXdNREF3TURCYU1Fb3hDekFKQmdOVkJBWVRBa05JTVE4d0RRWURWUVFIREFaYWRYSnBZMmd4RkRBU0JnTlZCQW9NQzFCeWIyTnBkbWx6SUVGSE1SUXdFZ1lEVlFRRERBdHdjbTlqYVhacGN5NWphREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQ2tTU0YxUHFjaEhCMUVVVVVPZUkwNGZUMDA1Z1dLSU9lNjBBOWJnckw4S2QzMURaY1JTcWF4QVVHQnQ3MEhCN3VDWmR1ZkE2dUtkTDZCdkF6VWhiSldqZ2dIaU1JSUIzakFPQmdOVkhROEJBZjhFQkFNQ0I0QXdGUVlEVlIwbEFRSF9CQXN3Q1FZSEtJR01YUVVCQWpBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRk8wYXNKM2lZRVZRQUR2YVdqUXlHcGktTGJmRk1Gb0dBMVVkSHdSVE1GRXdUNkJOb0V1R1NXaDBkSEJ6T2k4dlkyRXVaR1YyTG0xa2JDMXdiSFZ6TG1OdmJTOWpjbXd2TkRCRFJESXlOVFEzUmpNNE16UkROVEkyUXpWRE1qSkZNVUV5TmtNM1JUSXdNek15TkRZMk9DOHdnY29HQ0NzR0FRVUZCd0VCQklHOU1JRzZNRnNHQ0NzR0FRVUZCekFDaGs5b2RIUndjem92TDJOaExtUmxkaTV0Wkd3dGNHeDFjeTVqYjIwdmFYTnpkV1Z5THpRd1EwUXlNalUwTjBZek9ETTBRelV5TmtNMVF6SXlSVEZCTWpaRE4wVXlNRE16TWpRMk5qZ3VaR1Z5TUZzR0NDc0dBUVVGQnpBQmhrOW9kSFJ3Y3pvdkwyTmhMbVJsZGk1dFpHd3RjR3gxY3k1amIyMHZiMk56Y0M4ME1FTkVNakkxTkRkR016Z3pORU0xTWpaRE5VTXlNa1V4UVRJMlF6ZEZNakF6TXpJME5qWTRMMk5sY25Rdk1DWUdBMVVkRWdRZk1CMkdHMmgwZEhCek9pOHZZMkV1WkdWMkxtMWtiQzF3YkhWekxtTnZiVEFXQmdOVkhSRUVEekFOZ2d0d2NtOWphWFpwY3k1amFEQWRCZ05WSFE0RUZnUVVoSVZ4XzRLOHVEU2dUTG4yZnhaT2VaaWxhSkV3Q2dZSUtvWkl6ajBFQXdJRFNRQXdSZ0loQUlNUlllcmhWNWYtdGRwbVpuZjRYRXRLVmQyMUQzVlpwcGNNbHNpcHBYNXdBaUVBMnJJV3FnQWpla1JMcWYxaGM5bjlSSFV3eklnVnF1OVplc2FCSDZkcWhieFpBVkhZR0ZrQlRLWm5kbVZ5YzJsdmJtTXhMakJ2WkdsblpYTjBRV3huYjNKcGRHaHRaMU5JUVMweU5UWnNkbUZzZFdWRWFXZGxjM1J6b1dSMFpYTjBvUUJZSUNPSVpMdlZTaUJCWnNVTHo0VTluQnZDZUxnV0FScVFZeE9RWTdCQkxIQWxiV1JsZG1salpVdGxlVWx1Wm0taGFXUmxkbWxqWlV0bGVhTUJBU0FHSVZnZ0dFMXZRVS13MDZmc1o4WVZpS3hrTnc3MXduY1BaUmpDdW9oTXJIVDBvdEpuWkc5alZIbHdaWFZ2Y21jdWFYTnZMakU0TURFekxqVXVNUzV0UkV4c2RtRnNhV1JwZEhsSmJtWnZwR1p6YVdkdVpXVEFkREl3TWpRdE1URXRNVE5VTVRRNk1qVTZNVEZhYVhaaGJHbGtSbkp2YmNCME1qQXlOQzB4TVMweE0xUXhORG95TlRveE1WcHFkbUZzYVdSVmJuUnBiTUIwTWpBeU5DMHhNUzB4TmxReE5Eb3lOVG94TVZwdVpYaHdaV04wWldSVmNHUmhkR1hBZERJd01qUXRNVEV0TVRSVU1UUTZNalU2TVRGYVdFQnpBc0tGNGVKZzdFNFJTdUx4RjJDQk5YZzdpWUREMklsN3dTN1dkLXJVa2VQbWRjS1Jld0VQX3ZVSjlmbVRlLV9SYmZUM0dkeTV1Yndtbl9qTDY4TmxiR1JsZG1salpWTnBaMjVsWktKcWJtRnRaVk53WVdObGM5Z1lRYUJxWkdWMmFXTmxRWFYwYUtGdlpHVjJhV05sVTJsbmJtRjBkWEpsaEVPaEFTZWc5bGhBV2Z6c00tOEI0SF9xLTRXdVJnZVlQbjNhNEMydUxjQkdKam1qV3FJSTFGeS1tb0JOcV9FU3FkTkcycFZGYlZoVkh1Nm9pTUxLU0FFRHh2WHNjRlJUQkdaemRHRjBkWE1BIiwicHJlc2VudGF0aW9uX3N1Ym1pc3Npb24iOnsiaWQiOiJiOTE0NWEyYS00MDY0LTRhZjMtODY5Yi0xYzhkMmZkOGUzYzciLCJkZWZpbml0aW9uX2lkIjoiYzQ2MzU1NTMtMjQ5Ni00ZGIwLTg5OWUtNTFkZDkyNDJiZjZiIiwiZGVzY3JpcHRvcl9tYXAiOlt7ImlkIjoiaW5wdXRfMCIsImZvcm1hdCI6Im1zb19tZG9jIiwicGF0aCI6IiQiLCJwYXRoX25lc3RlZCI6eyJmb3JtYXQiOiJtc29fbWRvYyIsInBhdGgiOiIkLnZwLnZlcmlmaWFibGVDcmVkZW50aWFsWzBdIn19XX0sInN0YXRlIjoiYzQ2MzU1NTMtMjQ5Ni00ZGIwLTg5OWUtNTFkZDkyNDJiZjZiIn0";
        let expected_header = Header {
            key_id: "eec37767-ad74-47c9-a349-d95a1bd241d4".to_string(),
            agreement_partyuinfo:
                "\u{18}G\u{7}Ëcr\u{5}Þ§ù\u{97}~Ê0W>9FÖ=\u{17}¹v\u{7f}®ô\u{c}h\u{1c}u\u{99}Ç"
                    .to_string(),
            agreement_partyvinfo: "bueFnxmWT1EJEmPB5zq4m6aqkhEjIN8j".to_string(),
        };
        let jwe = "eyJraWQiOiJlZWMzNzc2Ny1hZDc0LTQ3YzktYTM0OS1kOTVhMWJkMjQxZDQiLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjoiR0VjSHc0dGpjZ1hEbnNLbnc3bkNsMzdEaWpCWFBqbEd3NVk5RjhLNWRuX0Nyc08wREdnY2RjS1p3NGMiLCJhcHYiOiJZblZsUm01NGJWZFVNVVZLUlcxUVFqVjZjVFJ0Tm1GeGEyaEZha2xPT0dvIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiM0JNNlpmcGU0S1FnUmJWMWVQbFc4M0dNX0xXU3VIWGpTWWwwTEVXeEdFSSIsInkiOiJmWmFlQW95MGd2M2xNd3VWaWpFSGNJejJvMk9xcE0yWXB3MFBrenFTREhZIn0sImFsZyI6IkVDREgtRVMifQ..FanNHP6n423XnuTq.olGWlNYGVyKkQsXcokpxvD_3iy_eVKXOPmmbveZkqYzHMi-OnNJXQ5ppbrzL43Mj9AqJFmMuKaQ1tHrsTfK_nPr_cuGn2qd4Xo-Y027Ij0jff5cFCf_9AtLLz8zlIYsKJTm97otqH3dXwfDNA7QZAIV6zOMPHzOGQj1186edqPukjkslFhVvxnqvc5Ukq2qheAYlc9sK2k38dAWSpVARFZxGjE8c7V_lXS6RqDQjX48677je0LXyfi6VrJ1M78fTfWhP3mjtuLWUGM9_94E1xlb6RZaW8Iz16Efbl6RxBpC-9ogDG9id8IAfzeKlGEVTepfnRlNovTb0j8kAyhfQ5KZQRN9x6_ltzoGb8MNknx6CeU29aqpiek1kADqFn0O6LMhKDEVNncNth2loPh8Fvjd3TOJwx9b1j2KsfgW3hwST8O4el529rkidW1GKZ4sF5bGV07QiDFC_BPDgmpon9diwL9t-z6EXzvksi9WVyQqCOvjNp-EoQvgcfkwvl-lgCOFR7cAKbX6L-NlP6wz20btIILE0238lnYTFL4oPVDJnt9RspFVrMs-8hifUsAAzqxt2oy6JIqRKmZjqJyBN2JauREV4L3fbkJrgqo6qtneEVeRXk9TGhoSS-ZVajIFlIpw7d-ufs-odR8cIuRX2mWKoAX6cC7WCCKALIzT_CbvWXmTkGmZk7CRCoRQgIPveazy5JY-M8-501rabzF-980IHyDYn3OvzBXzY2MUgfWvhVhdZHJR8fmAWYJehf8v3uTUeJHtuPQAQYCt0Wwgqz71dusfCBjPmVpsu9G8Gkd6kWMiQDIVH0iF9sGJlDZCu2SouPF8pixB3PvpeM_sXBaFqqT9vZEEV0c5yppgpvTsd-rWNWiz1AZ5rFDsh0h1qx68OcGg6ZV3LBX4hNp0yQn2ekh6v_1pnJJufyME9_hwRezlE-do_E2Xi-SjEFpBnk5od_MtCdAzAAUKJMDPuBIzN9Xdu2F9EAiyzP7FwiCGYcrnO8c9TGdFCjOMUhrxOvJ62Kdp7UAQEdRKCGD3KW9py5gF5WLs_WOiNDta5CImHwomscLo9TBntSYqXvDnm-xlCXNkYvL7E2ZBVFkSrGgqjoKqwYP4Uo6TfIPWtr-NHFnISzUuYweM-NUV_XT35DgZME98f-vzPo47sX6fOH6CaTEcGv1alLOsE9XVPs-U87GreE70JtDsAKgCyCGk7oI_3EhdOjrBEzUYuwYdZj4EJ1jhhNYuvJMZWg0KxOof90MUAXZZpN3RA_1by99Z0r_PW34VJkE6Y-TdA70qjhWoZcLOOZlX2iUqIEVsHb3m8mTSlF3llc5DpQnB9GKINWpuxR7s7XgJkDgb_Vjze5OFn1YTfJvhicc5yjsWZ072Rd0i9OPdJqpMmB9tgiN57PyhrLLD3Rx88QbXf9n50lYnkTLJtFZ0sDx-U58L6HdqE2Xio4mjdoVy_1_H2nDIP0W_17k-qYQwUJIcP1V7sZNr0l8S3IQqZhARw3VmlM7WrkeWD0laonIQok7T4Ue39-3D3NmP6VPFvJx_hk-lYiXNrcmlAo-RgvJLdzyFw3ekbSqyfzFt33PBm0htwErkO5nN68eyAYIZ6A6LyToZwA0JhZh6MqftqlGHsRG3XtrEfvrd94DymLjLp6rmKpMgHBQSzwYSp15VN16oSP40eUWWVXbsrEhxjXD-iCn-Zz5K35A3NDQsIS5712FD5lRbqf0LWVSsdNYy0gr5A7bC3ePbkmBzOWPcDiLDq8sO4fleavT4jNjGviSfGwFFONwpKEgVKM8KOb5f8Ric9V-GmqmXIDsv3NYDYAR1GJHkrJ-lN4txLLruosKT490NV7EdaNxqQKSbBlGoh6UNT71SdN2IqqIfup5fDndReMl05Mlb9feUkqC6UWl6H3LShHiuZKXwIY-ZNtSAmokBze3LRkyHB66pZgE7krAUEyVX7DnpxaBgCrrA7tK2Kuo3aYcjXjOIpHHplORwPoUsHB_bBeinsYX6U5PKvvOIsokJOppNbwyeqABEhao7uiBeSiqzNa0iHPrTqTcTDxkl4HcQgq_y_P8LAZTZjW9713W5ujS-OyRef3VO15rm9QH6wkP4WR532Ep126soW429q9e0b5Q3ECB7Wg8FsX2IJoAsrPELPaJ_cHbzRNiecxF-lbG8Tf6mkagY5dQq9tEocdT52FVimhHg4DOfVyhWNw9VzVtGkyXxARjw4o89qR0kS0dnTIwD7609Kftmux44xhNXeWNMTlPzleOZGa1-65zEth2X9BhVFWzD92dMBLJRWPRRq7eBLG2X3oQMLRmMigkxq0KenZUK7GBDaRLj-JXSXyOhs0ZyA2AN5Y7Kntdq7fC_ZiWS-WiU495f9y0WqveRJF-NwWulOJ5LMdIwvNDinrbHUSKZZIdqI32JtAMgcrj4KiK3yjHfufL0N7zwwu6U6ezqJikSn0q5ptxcJVmNoi6nkycYOnW17c029IOiTQokQWDOdgxo4PjcZUD-XvCib2a-znLIEfio3LyWC9ZAgm02_3PttaHxR4jRdtKXy4EEZ-kNqBstVJqm0eW1o3abjUmm3ZYwtFdbFuRbI_y3mIwrVlkq8eeuosab76gCB171-VYYNAqnt_ERvsBHeLzv0-8DrKh5n6mmjVn-hbr8NgLyUhCuwZqDJvc3Cru-UwZLxwjrYIpRHoCK5K_92u8-QcSdZ-9Oz6PCBNUAssjzEyCrmcPnI6J0tj_Iacrj91m_Ytp17aIS16kCqwKQgfpa1E4tYbepPvO9TwQNq-zrgQhMvy2muZxrfYRvFqo6GVvBmLf4A1811szaTv3KPv86TdM_0E-cjCbwoBUWAVgy_cb5-7r5rRTObbVhA8oxrq8F_LSVMJLh9DyszpNHMpJiisdmzELWjqIUOFqP1nJBOojbI7Db-YlN_utfBVW0fZB5iB6rzioQopkHViKbZYW1wfPLyHcLW1Ddqdj2WWDnR770CpLxMgCzfrOshF4Kosz1rgCCv-PjpXuq7ht5_5hdK6kHcIyj-gr1xPAoojPbscjPrcJJQNyy79qoQfTHqI8zDoCqNTtJn-7UGCmDd8y7x_NeUf4EijrKujuHoXz3P_6ZHSP7syHUIoGsyVj9YK8U5oQKEssCHNL6YmR9iPwefLSfEIqnUghUaIUnULrU7sHDq0oF64ImvQEMK_jRY5L-Aa1Uu7wsotYoW2K-JUw8lKPBQuykfR3CJnwb9wN7IHKUV8AWwIwK_PUry7fhoRjQESbgj1xqZVpy1oJEmo9N-dm470oOyTwhU7NqknObJB88QhiumBBcTIlm6FkPunw1vIBNlBSVD_p9zoUJiBhLljnTfbYOFKxNTj2EgJsYIhQqepA923DPQqsm_vHlIwQeIRHV6WHpDULsiWeHHrDIf57pUy73oN38rEQQiCB86lHXGscnyJum3itzSF8dMf852lGZyaMSXqX2sUCY-dsf-wsfQlfkSVK3Hi1hxmFgCTarRY_qnZLCQktM.DshBdcfiHuDRQlCAJMDNBQ";

        let extracted_header = extract_jwe_header(jwe).unwrap();
        assert_eq!(expected_header, extracted_header);

        let decrypted_payload_bytes = decrypt_jwe_payload(jwe, PRIVATE_JWK_EC).unwrap();
        assert_eq!(
            Base64UrlSafeNoPadding::encode_to_string(decrypted_payload_bytes).unwrap(),
            expected_payload
        )
    }

    #[test]
    fn test_decrypt_jwe_eddsa() {
        let expected_payload = "eyJhdWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9vaWRjLXZlcmlmaWVyL3YxL3Jlc3BvbnNlIiwiZXhwIjoxNzMxNTEwNzg5LCJ2cF90b2tlbiI6Im8yZDJaWEp6YVc5dVl6RXVNR2xrYjJOMWJXVnVkSE9CbzJka2IyTlVlWEJsZFc5eVp5NXBjMjh1TVRnd01UTXVOUzR4TG0xRVRHeHBjM04xWlhKVGFXZHVaV1NpYW01aGJXVlRjR0ZqWlhPaFpIUmxjM1NCMkJoWVg2Um9aR2xuWlhOMFNVUUFabkpoYm1SdmJWZ2dBQnBqa1h3Q2RYdVJUdUlaU3RqWnRCZ0dhZ3FqcFlpeGMxSWFINUpRY1JweFpXeGxiV1Z1ZEVsa1pXNTBhV1pwWlhKbWRtRnNkV1V4YkdWc1pXMWxiblJXWVd4MVpXUjBaWE4wYW1semMzVmxja0YxZEdpRVE2RUJKcUVZSVZrRGx6Q0NBNU13Z2dNNG9BTUNBUUlDRkVQamdGUExNb1NmRk4xSVRPeDc0OUlKWWFtQ01Bb0dDQ3FHU000OUJBTUNNR0l4Q3pBSkJnTlZCQVlUQWtOSU1ROHdEUVlEVlFRSERBWmFkWEpwWTJneEVUQVBCZ05WQkFvTUNGQnliMk5wZG1sek1SRXdEd1lEVlFRTERBaFFjbTlqYVhacGN6RWNNQm9HQTFVRUF3d1RZMkV1WkdWMkxtMWtiQzF3YkhWekxtTnZiVEFlRncweU5ERXhNVE14TkRBMU1EQmFGdzB5TlRBeU1URXdNREF3TURCYU1Fb3hDekFKQmdOVkJBWVRBa05JTVE4d0RRWURWUVFIREFaYWRYSnBZMmd4RkRBU0JnTlZCQW9NQzFCeWIyTnBkbWx6SUVGSE1SUXdFZ1lEVlFRRERBdHdjbTlqYVhacGN5NWphREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQ2tTU0YxUHFjaEhCMUVVVVVPZUkwNGZUMDA1Z1dLSU9lNjBBOWJnckw4S2QzMURaY1JTcWF4QVVHQnQ3MEhCN3VDWmR1ZkE2dUtkTDZCdkF6VWhiSldqZ2dIaU1JSUIzakFPQmdOVkhROEJBZjhFQkFNQ0I0QXdGUVlEVlIwbEFRSF9CQXN3Q1FZSEtJR01YUVVCQWpBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRk8wYXNKM2lZRVZRQUR2YVdqUXlHcGktTGJmRk1Gb0dBMVVkSHdSVE1GRXdUNkJOb0V1R1NXaDBkSEJ6T2k4dlkyRXVaR1YyTG0xa2JDMXdiSFZ6TG1OdmJTOWpjbXd2TkRCRFJESXlOVFEzUmpNNE16UkROVEkyUXpWRE1qSkZNVUV5TmtNM1JUSXdNek15TkRZMk9DOHdnY29HQ0NzR0FRVUZCd0VCQklHOU1JRzZNRnNHQ0NzR0FRVUZCekFDaGs5b2RIUndjem92TDJOaExtUmxkaTV0Wkd3dGNHeDFjeTVqYjIwdmFYTnpkV1Z5THpRd1EwUXlNalUwTjBZek9ETTBRelV5TmtNMVF6SXlSVEZCTWpaRE4wVXlNRE16TWpRMk5qZ3VaR1Z5TUZzR0NDc0dBUVVGQnpBQmhrOW9kSFJ3Y3pvdkwyTmhMbVJsZGk1dFpHd3RjR3gxY3k1amIyMHZiMk56Y0M4ME1FTkVNakkxTkRkR016Z3pORU0xTWpaRE5VTXlNa1V4UVRJMlF6ZEZNakF6TXpJME5qWTRMMk5sY25Rdk1DWUdBMVVkRWdRZk1CMkdHMmgwZEhCek9pOHZZMkV1WkdWMkxtMWtiQzF3YkhWekxtTnZiVEFXQmdOVkhSRUVEekFOZ2d0d2NtOWphWFpwY3k1amFEQWRCZ05WSFE0RUZnUVVoSVZ4XzRLOHVEU2dUTG4yZnhaT2VaaWxhSkV3Q2dZSUtvWkl6ajBFQXdJRFNRQXdSZ0loQUlNUlllcmhWNWYtdGRwbVpuZjRYRXRLVmQyMUQzVlpwcGNNbHNpcHBYNXdBaUVBMnJJV3FnQWpla1JMcWYxaGM5bjlSSFV3eklnVnF1OVplc2FCSDZkcWhieFpBVkhZR0ZrQlRLWm5kbVZ5YzJsdmJtTXhMakJ2WkdsblpYTjBRV3huYjNKcGRHaHRaMU5JUVMweU5UWnNkbUZzZFdWRWFXZGxjM1J6b1dSMFpYTjBvUUJZSUNPSVpMdlZTaUJCWnNVTHo0VTluQnZDZUxnV0FScVFZeE9RWTdCQkxIQWxiV1JsZG1salpVdGxlVWx1Wm0taGFXUmxkbWxqWlV0bGVhTUJBU0FHSVZnZ0dFMXZRVS13MDZmc1o4WVZpS3hrTnc3MXduY1BaUmpDdW9oTXJIVDBvdEpuWkc5alZIbHdaWFZ2Y21jdWFYTnZMakU0TURFekxqVXVNUzV0UkV4c2RtRnNhV1JwZEhsSmJtWnZwR1p6YVdkdVpXVEFkREl3TWpRdE1URXRNVE5VTVRRNk1qVTZNVEZhYVhaaGJHbGtSbkp2YmNCME1qQXlOQzB4TVMweE0xUXhORG95TlRveE1WcHFkbUZzYVdSVmJuUnBiTUIwTWpBeU5DMHhNUzB4TmxReE5Eb3lOVG94TVZwdVpYaHdaV04wWldSVmNHUmhkR1hBZERJd01qUXRNVEV0TVRSVU1UUTZNalU2TVRGYVdFQnpBc0tGNGVKZzdFNFJTdUx4RjJDQk5YZzdpWUREMklsN3dTN1dkLXJVa2VQbWRjS1Jld0VQX3ZVSjlmbVRlLV9SYmZUM0dkeTV1Yndtbl9qTDY4TmxiR1JsZG1salpWTnBaMjVsWktKcWJtRnRaVk53WVdObGM5Z1lRYUJxWkdWMmFXTmxRWFYwYUtGdlpHVjJhV05sVTJsbmJtRjBkWEpsaEVPaEFTZWc5bGhBdkd2MUUwanZOR05ZY21wbllqMWRKRUJ5MFZ2alJZWkNXWm1pdWRpRC1ETEdyQi1lc1JNUjhIRG9hWGx6R0xEcW5hbEVRQVQyNV82MzN5blpMcUVmQ21aemRHRjBkWE1BIiwicHJlc2VudGF0aW9uX3N1Ym1pc3Npb24iOnsiaWQiOiJkYmEwZTQ5MS1iNjk5LTRkM2UtYTQ0YS01MTg4OWE2MmQzNmIiLCJkZWZpbml0aW9uX2lkIjoiZGFkZTE1MmItYjg1NS00NWNiLWJkZjAtNTIyZmUxNWMwOWI3IiwiZGVzY3JpcHRvcl9tYXAiOlt7ImlkIjoiaW5wdXRfMCIsImZvcm1hdCI6Im1zb19tZG9jIiwicGF0aCI6IiQiLCJwYXRoX25lc3RlZCI6eyJmb3JtYXQiOiJtc29fbWRvYyIsInBhdGgiOiIkLnZwLnZlcmlmaWFibGVDcmVkZW50aWFsWzBdIn19XX0sInN0YXRlIjoiZGFkZTE1MmItYjg1NS00NWNiLWJkZjAtNTIyZmUxNWMwOWI3In0";
        let expected_header = Header {
            key_id: "9be052ed-83b8-4c60-ab4f-214fe21caa93".to_string(),
            agreement_partyuinfo: "BJ\"ûzw\u{11}\u{93}\u{7}Ç>»Ý%\nÁk&âÌÕ°\u{6}\u{9e}Õ_\u{8a}Ö%#Za"
                .to_string(),
            agreement_partyvinfo: "e4xmMaGk6O2UX25eq7Opc46LU7PdzUXp".to_string(),
        };
        let jwe = "eyJraWQiOiI5YmUwNTJlZC04M2I4LTRjNjAtYWI0Zi0yMTRmZTIxY2FhOTMiLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjoiUWtvaXc3dDZkeEhDa3dmRGh6N0N1OE9kSlFyRGdXc213NkxEak1PVndyQUd3cDdEbFZfQ2lzT1dKU05hWVEiLCJhcHYiOiJaVFI0YlUxaFIyczJUekpWV0RJMVpYRTNUM0JqTkRaTVZUZFFaSHBWV0hBIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJteHBhUW5zWjZFYWFUR3Y5aU1NZmQ3dGJrSUNDR1FqLUVQVGRxeDlnLTBRIn0sImFsZyI6IkVDREgtRVMifQ..yaYKT82f_9fNheZO.N3vMRP6gEbieETK9FcFdd4vF6G7rOmE_8HTGlSOncrEUsBTi6bl5mM80FSiLYwhj-EhwfKvl9AkBukWTtndMVku3dDMnK2Wn4cvjZzQE0Vqu2JyYHFsUQ9H8i-sxetfGepvIbmokN3Ihdv0w_ffTrRrpfosYunkRBBdpElTl5T2B9Goo-r4W9wWLD_2gQnVTIc8Ps2HeJbGt8kYCJyKeuyzGs9JSaHkx_pEaRU40oZKnAnwg0E6Yl394tj-tZ427_iNFhP02K5_EXFHGOLfmEVSrs3eodNzzkXH8VXqzm2ytC_g8BoIlsW6A7sudKfzYptob_lerxCxozvW06bLD-9v4PaNcA4YrShOoJsIlSIJ7ttWPInEXCl44XJS3ASKzg00oI5StDAS_AkE9rgnOkirZTRXma2NIhcNliYOzZbhcWaRYLPHunRi99Eon3rrjp3BDa6pZjMW9_dF8UzQFdQCJEWNEVuczzxCm8KYFvroh3t3RHjhvi6HV3pjz6tEx3AWoie24zLaogArtoLenqmAFF-HW_rXistJ7Rl16oksF3Yj6OhsYPkIK4tx2WnC7TNjU4GbJbIU7Z9nIjkGpgITOizW4Ps9-UZBV4gYmj8tgT1RCWbHWoC7nk2V0Mf2spKAToAzZseMYXCl35DBu0mX0h_b-AGAjVL1xhL6rtg6srlGU9cM5X4olqiHzp05vmgVJbNyQhc2wpbknMEyz0v4OTRWL5s_-Yst7rmvKtzl9JmhecE7wwmaYaqRbz5qBosPJ4zdo1RMDfnQyVIRXiMODpQUvzjANwH9YdvYU2KHFiaprbqonwrYZmoHzEqHNFZ8htzcYIZWv-4611gV4x9E_ZjtPyYQCw7RkLbokKgcwRGGRadAkznSnMWAgWJDOgx20wzsMo2WwljSScUUX-nE6itftNxcrfdR0ItwGy6558iQ_9_QJ0tkABKtu3Eb9SMkLcl5NjRn3QSJsHHumst-OD3RmCoJ_FdQzKTDAftGDeVhwhFwGdFYNWvJ-wsSUqHLnqaNIruJKPPxMrAh74nmcrn7506gtFTDzd0a4_mWjKaqHYpbZa7XLmiOPj9jd4jFTuCcSwMFu__NKsQIDMXrTQ9ddY3G6qLi8oWKP8RrgGZUvcpUYT1X1k7JO9POOghWhyvUQQJIUFWEiWxew86Owp_w9Gu4_mRg15FT8h2OEKqpHuEN7lZiaBsN5Q6dLITA4Sv98SUPZ9lD4pFW2kQLz-jgSyK7umzj-HCYb5tdrRZIcfNB91537KE7hGhA7UfzkZIw1kPuewn9KtVittXYH_CjLUTA4F0LbYZq9CwORKNsT36A06TLB2xB_VyRGNHNz5BvjfrFZJ4wyU76uS-a7_tf_y2VoaXEmRPYoBCBjpa4aW7yeDIVWIqe2vuqRN0kmY0FeYJ33jzSTVksiK1--zKvJhghek5eBmZh7Qi8PYUZvooTr19fGnveMbV7eoXGIk-_OO_vrMLchd1G3CgILlpUMjFRuSoBQWblebo3RaOTcH-rI1FXOm2L1IDezcL3oLhoGF9HGiIaq48DSI7lcG5Tkq1G2uzPWtkCG20aRFInxEMTIfTvEV0IG_oQl_F162ETkRhXQu0UdGD1gpBJiGoOCPY57g6xfINEutxesvG1Cfx8Nc0nW4wxHEU8RZRgdU2S7h8xpyDLKVLXB6Kikj8wZ9c5kGEipzNbip22rXZlJXthdKd_re70sKPAG6k_YpH4YGSSwcYSfnEHeJrlZx7-LfnLm0iTkRFuakLxCqmz3Hz1VddSQE37SDTW9wqNaa4wNq5zrvIBqSR14xgba5NZJDqKJC_493B6FQGyAY8L_4LceL4WWJw32otCojSWdChFMTiON2UHYeNKafbe_0Pgx4KrBNNeIMM4-XKFTWGPCmJWrAWHU3aROJNGSHG3dCuC1tBLSWfULJg2zd0JXday3VPA0V-scSe7DV6YTUCNjgVJp-VJymajbE54lcYz_REjCgyl9vI1LQ8uLsEHm4NKPq-93l4OBj2p1OARlLPvnn0kv_64eDa6p14FFImPnV25UqYWrzJh_0b3XLl9L-rPHLpjxun1k1i7zzDr0fuGQ3QzJXgb8Qf_krJ4J8Wz-Ftz5pU80KP0gcwlYMLf1EPsmC91N3KBXKJUMvTQirbmQPbMR85cInlshR4ksYZ55uaoqP7-byJxuCte56_B0othvxcsqsh50bMGE7T9XPCTL1UWZLnKtd6UXTk-mkyafrTOJXocjemtOAb8-P07G6ep0llejBlIQ5c9iByOfL-3DBMi3EKF0NWyixHydMzXH9Dlt2ZMqeZHcpk8paCtOGDQFdmSsbarm1eQCscqSt8VcG2rAhzSKfgFr0eT8r1EZBoIyG7oMJsfnFmAw2KsYSuAzG3z3bvwGJio9zuIP2lHHDBIA2ooAOK9V4Ppb2WjLkXuZXfGuZenEYEgM6NLxbzdGCwbnqV3IDvoQ0120gAt9dR8zVMUzFRqE6i2cvMTHn25thGKUVPAjB5goexd_9986IDDndtLk1badlAjG7_ZjBIxtqgUyNyFkM4YLDT0KVk6cCbk6VPozpgvx_k1YSKzW-8YpoO5A6rETIOGBrVG3GNdVBEZJN41JqHTNM-oi9UX7Pk6lg0ZwLKmsvaXiYLVKzP2OGezuHlipv_seBgb-HJh1d8AJUCdgj-WQ1BVusuMDUnSsQTnOyvp7Ziu6QB2xGDNEq9rdwtwagNj3EHls7RkqWane5GgHX8r4qDrQsuM2rnqydllM6Ge-pK--XupLBzjSmVXhp-MMDSovDuYOThcUeydKnpEbGCq7XRJyYbvYDbQ20d4WAysBcxR3B04oUxLWxfmrRcwUdVGT6wMEBGTtUYFfvi9GyASZkEq9FmwiG1omijIn-sxwKkCzO9V5RcnfeHFGNLGizqq-GGjdbWck3W9sly8YpmDvdFH1pUcpHyGC45d5r8d9lpg_qwuqy3XEE3qPs094qOGsGbVAf1AzMIR0P7lY-CRmUXjcxyOzpHA7r2vSJk15zxp9ffYc6CR-Sf2qhnEAEFridprCZQa7cfPVAEeppbmiRKqTex177f2qQWA08YIS0E5GSDg-FEs7jnXlCutrxzTFVetBu7Ocz_7ul6b3ouks5qPy-NYl08IOfKEmAIW1NDWNBBZcaQf6zt5SQOEpfdrvkx0Nu9n1i0Dd90SXXmKOsle2NBr-zQB5Ak4ai1-31KBpNBj2gU7TD1elGrKkPjhllzJh2hBXeSkBV4fg5O95ci6UUHVvwLsL_CeNpBbraUsYQfPPlb7ZMVGLYz0eBl_CKGHONZ9atFmbYL_ZmtcbX0d1ItHRQzoZnAsqWtzdPw7mjaOj8Me40BmLclGs2sZsa8Dn5pcrHExiDGfu1cUM3xZvmdax0TMaSX5z91lB8_nSDV6hJ0IA3qWF95Xwq7aDfkI63dIDbKpYOc_u0wKDO0rVnk-WFfla2FDAU2TYDsEgJeBzH9kc1KEHmEdnmpVkrUY46oyTSpA.I8IjDxf1r15-nUOugLRFAg";

        let extracted_header = extract_jwe_header(jwe).unwrap();
        assert_eq!(expected_header, extracted_header);

        let decrypted_payload_bytes = decrypt_jwe_payload(jwe, PRIVATE_JWK_ED25519).unwrap();
        assert_eq!(
            Base64UrlSafeNoPadding::encode_to_string(decrypted_payload_bytes).unwrap(),
            expected_payload
        )
    }

    #[test]
    fn test_jwe_round_trip_ec() {
        let payload = b"test_payload";
        let header = Header {
            key_id: "eec37767-ad74-47c9-a349-d95a1bd241d4".to_string(),
            agreement_partyuinfo:
                "\u{18}G\u{7}Ëcr\u{5}Þ§ù\u{97}~Ê0W>9FÖ=\u{17}¹v\u{7f}®ô\u{c}h\u{1c}u\u{99}Ç"
                    .to_string(),
            agreement_partyvinfo: "bueFnxmWT1EJEmPB5zq4m6aqkhEjIN8j".to_string(),
        };
        let recipient_jwk = RemoteJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "KRJIXU-pyEcHURRRQ54jTh9PTTmBYog57rQD1uCsvwo".to_string(),
            y: Some("d31DZcRSqaxAUGBt70HB7uCZdufA6uKdL6BvAzUhbJU".to_string()),
        };

        let jwe = build_jwe(payload, header.clone(), recipient_jwk).unwrap();
        let extracted_header = extract_jwe_header(&jwe).unwrap();
        assert_eq!(header, extracted_header);

        let decrypted_payload_bytes = decrypt_jwe_payload(&jwe, PRIVATE_JWK_EC).unwrap();
        assert_eq!(payload.as_slice(), decrypted_payload_bytes);
    }

    #[test]
    fn test_jwe_round_trip_eddsa() {
        let payload = b"test_payload";
        let header = Header {
            key_id: "9be052ed-83b8-4c60-ab4f-214fe21caa93".to_string(),
            agreement_partyuinfo: "BJ\"ûzw\u{11}\u{93}\u{7}Ç>»Ý%\nÁk&âÌÕ°\u{6}\u{9e}Õ_\u{8a}Ö%#Za"
                .to_string(),
            agreement_partyvinfo: "e4xmMaGk6O2UX25eq7Opc46LU7PdzUXp".to_string(),
        };
        let recipient_jwk = RemoteJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "0yErlKcMCx5DG6zmgoUnnFvLBEQuuYWQSYILwV2O9TM".to_string(),
            y: None,
        };

        let jwe = build_jwe(payload, header.clone(), recipient_jwk).unwrap();
        let extracted_header = extract_jwe_header(&jwe).unwrap();
        assert_eq!(header, extracted_header);

        let decrypted_payload_bytes = decrypt_jwe_payload(&jwe, PRIVATE_JWK_ED25519).unwrap();
        assert_eq!(payload.as_slice(), decrypted_payload_bytes);
    }
}

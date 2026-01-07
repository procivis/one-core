pub fn dummy_registration_certificate_payload() -> serde_json::Value {
    serde_json::json!({
        "name": "Jane Doe",
        "sub": {
            "given_name": "Jane",
            "family_name": "Doe",
            "id": "TIN-1234567890"
        },
        "info_uri": "https://example.com",
        "country": "DE",
        "privacy_policy": "https://example-company.com/en/privacy-policy",
        "policy_id": [],
        "certificate_policy": "https://registrar.example.com/certificate-policy",
        "purpose": [],
        "credentials": [],
        "entitlements": [
            "https://uri.etsi.org/19475/Entitlement/PID_Provider"
        ],
        "service": [],
        "status": {}
    })
}

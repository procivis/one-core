#[test]
fn test_base64_salt() {
    let result = super::utilities::generate_salt_base64_16();

    // set for Base64 url no padding
    let allowed_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    assert!(result.chars().all(|c| allowed_characters.contains(c)));
}

#[test]
fn test_alphanumeric() {
    let expected_len = 254;

    let result = super::utilities::generate_alphanumeric(expected_len);

    // alphanumeric
    let allowed_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    assert!(result.chars().all(|c| allowed_characters.contains(c)));
    assert_eq!(result.len(), expected_len);
}

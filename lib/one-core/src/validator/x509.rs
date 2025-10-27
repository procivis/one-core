pub(crate) fn is_dns_name_matching(dns_def: &str, target_domain: &str) -> bool {
    // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.3
    if let Some(wildcard_domain) = dns_def.strip_prefix("*") {
        target_domain.ends_with(wildcard_domain)
    } else {
        // simple case
        dns_def == target_domain
    }
}

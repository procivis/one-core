use time::OffsetDateTime;

pub struct GenerateCSRRequestDTO {
    pub profile: GenerateCSRRequestProfile,
    pub not_before: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub subject: GenerateCSRRequestSubjectDTO,
}

#[derive(PartialEq)]
pub enum GenerateCSRRequestProfile {
    Mdl,
}

pub struct GenerateCSRRequestSubjectDTO {
    pub country_name: String,
    pub common_name: String,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

use serde::de::{Deserialize, Deserializer, Error, Unexpected};

pub(super) fn calculate_pages_count(total_items_count: u64, page_size: u64) -> u64 {
    if page_size == 0 {
        return 0;
    }

    (total_items_count / page_size) + std::cmp::min(total_items_count % page_size, 1)
}

pub(super) fn bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"zero or one",
        )),
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::calculate_pages_count;

    #[test]
    fn test_calculate_pages_count() {
        assert_eq!(0, calculate_pages_count(1, 0));

        assert_eq!(1, calculate_pages_count(1, 1));
        assert_eq!(1, calculate_pages_count(1, 2));
        assert_eq!(1, calculate_pages_count(1, 100));

        assert_eq!(5, calculate_pages_count(50, 10));
        assert_eq!(6, calculate_pages_count(51, 10));
        assert_eq!(6, calculate_pages_count(52, 10));
        assert_eq!(6, calculate_pages_count(60, 10));
        assert_eq!(7, calculate_pages_count(61, 10));
    }
}

use time::OffsetDateTime;

pub fn now_utc() -> OffsetDateTime {
    #[cfg(not(test))]
    {
        OffsetDateTime::now_utc()
    }

    #[cfg(test)]
    {
        MOCK_TIME
            .try_with(|s| *s)
            .ok()
            .unwrap_or(OffsetDateTime::now_utc())
    }
}

tokio::task_local! {
    #[cfg(test)]
    static MOCK_TIME: OffsetDateTime;
}

/// run code while mocking each `now_utc` call to return the specified value
#[cfg(test)]
pub async fn run_with_mocked_time_async<T>(
    time: OffsetDateTime,
    future: impl Future<Output = T> + Send,
) -> T
where
    T: Send + 'static,
{
    let mut result = None;
    MOCK_TIME
        .scope(time, async {
            result = Some(future.await);
        })
        .await;
    result.expect("missing future result")
}

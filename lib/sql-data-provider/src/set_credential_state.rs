use one_core::repository::{data_provider::CredentialState, error::DataLayerError};
use time::OffsetDateTime;

use crate::{common_queries::insert_credential_state, OldProvider};

impl OldProvider {
    pub async fn set_credential_state(
        &self,
        credential_id: &str,
        new_state: CredentialState,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        insert_credential_state(&self.db, credential_id, now, new_state.into()).await?;

        Ok(())
    }
}

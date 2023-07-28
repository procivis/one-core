use crate::data_layer::{
    common_queries::insert_credential_state, entities::credential_state::CredentialState,
    DataLayer, DataLayerError,
};
use time::OffsetDateTime;

impl DataLayer {
    pub async fn set_credential_state(
        &self,
        credential_id: &str,
        new_state: CredentialState,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        insert_credential_state(&self.db, credential_id, now, new_state).await?;

        Ok(())
    }
}

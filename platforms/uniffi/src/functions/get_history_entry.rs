use crate::dto::HistoryListItemBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn get_history_entry(
        &self,
        history_id: String,
    ) -> Result<HistoryListItemBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .history_service
                .get_history_entry(into_id(&history_id)?)
                .await?
                .into())
        })
    }
}

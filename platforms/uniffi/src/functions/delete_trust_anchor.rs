use shared_types::TrustAnchorId;

use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn delete_trust_anchor(&self, anchor_id: String) -> Result<(), BindingError> {
        let trust_anchor_id: TrustAnchorId = into_id(&anchor_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .trust_anchor_service
                .delete_trust_anchor(trust_anchor_id)
                .await?)
        })
    }
}

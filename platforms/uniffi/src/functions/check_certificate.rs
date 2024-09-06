use crate::dto::KeyCheckCertificateRequestBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn check_certificate(
        &self,
        key_id: String,
        certificate: KeyCheckCertificateRequestBindingDTO,
    ) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .key_service
                .check_certificate(&into_id(&key_id)?, certificate.into())
                .await?)
        })
    }
}

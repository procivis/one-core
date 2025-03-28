use std::path::Path;

use one_core::service::backup::dto::{
    BackupCreateResponseDTO, MetadataDTO, UnexportableEntitiesResponseDTO,
};
use one_core::service::error::ServiceError;
use one_core::service::key::dto::KeyListItemResponseDTO;
use one_dto_mapper::{convert_inner, From};
use secrecy::SecretString;

use super::credential::CredentialDetailBindingDTO;
use super::did::DidListItemBindingDTO;
use super::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::TimestampFormat;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn create_backup(
        &self,
        password: String,
        output_path: String,
    ) -> Result<BackupCreateBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .backup_service
            .create_backup(SecretString::from(password), output_path)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn backup_info(&self) -> Result<UnexportableEntitiesBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core.backup_service.backup_info().await?.into())
    }

    #[uniffi::method]
    pub async fn finalize_import(&self) -> Result<(), BindingError> {
        if !Path::new(&self.backup_db_path).exists() {
            return Err(ServiceError::ValidationError("no active backup file found".into()).into());
        }

        self.uninitialize(false).await?;
        std::fs::copy(&self.backup_db_path, &self.main_db_path)
            .map_err(|e| ServiceError::Other(e.to_string()))?;
        self.initialize(self.main_db_path.clone()).await?;
        std::fs::remove_file(&self.backup_db_path)
            .map_err(|e| ServiceError::Other(e.to_string()))?;

        let core = self.use_core().await?;
        core.backup_service
            .finalize_import(self.backup_db_path.clone())
            .await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn rollback_import(&self) -> Result<(), BindingError> {
        if !Path::new(&self.backup_db_path).exists() {
            return Err(
                ServiceError::ValidationError("no active backup file found".to_string()).into(),
            );
        }

        self.initialize(self.main_db_path.clone()).await?;
        std::fs::remove_file(&self.backup_db_path)
            .map_err(|e| ServiceError::Other(e.to_string()))?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn unpack_backup(
        &self,
        password: String,
        input_path: String,
    ) -> Result<MetadataBindingDTO, BindingError> {
        if Path::new(&self.backup_db_path).exists() {
            return Err(ServiceError::ValidationError("backup file already exists".into()).into());
        }

        let metadata: MetadataBindingDTO = {
            let core = self.use_core().await?;
            core.backup_service
                .unpack_backup(
                    SecretString::from(password),
                    input_path,
                    self.backup_db_path.clone(),
                )
                .await?
                .into()
        };

        self.initialize(self.backup_db_path.clone()).await?;
        Ok(metadata)
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(BackupCreateResponseDTO)]
pub struct BackupCreateBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub history_id: String,
    pub file: String,
    pub unexportable: UnexportableEntitiesBindingDTO,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(MetadataDTO)]
pub struct MetadataBindingDTO {
    pub db_version: String,
    pub db_hash: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_at: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(UnexportableEntitiesResponseDTO)]
pub struct UnexportableEntitiesBindingDTO {
    #[from(with_fn = convert_inner)]
    pub credentials: Vec<CredentialDetailBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub keys: Vec<KeyListItemBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub dids: Vec<DidListItemBindingDTO>,
    pub total_credentials: u64,
    pub total_keys: u64,
    pub total_dids: u64,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(KeyListItemResponseDTO)]
pub struct KeyListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}

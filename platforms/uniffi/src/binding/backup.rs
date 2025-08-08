use std::path::Path;

use one_core::service::backup::dto::{
    BackupCreateResponseDTO, MetadataDTO, UnexportableEntitiesResponseDTO,
};
use one_core::service::error::ServiceError;
use one_core::service::key::dto::KeyListItemResponseDTO;
use one_dto_mapper::{From, convert_inner};
use secrecy::SecretString;

use super::OneCoreBinding;
use super::credential::CredentialDetailBindingDTO;
use super::did::DidListItemBindingDTO;
use crate::binding::identifier::GetIdentifierListItemBindingDTO;
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
    #[from(with_fn = convert_inner)]
    pub identifiers: Vec<GetIdentifierListItemBindingDTO>,
    pub total_credentials: u64,
    pub total_keys: u64,
    pub total_dids: u64,
    pub total_identifiers: u64,
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

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use crate::binding::backup::BackupCreateBindingDTO;
    use crate::binding::history::{
        HistoryActionBindingEnum, HistoryEntityTypeBindingEnum, HistoryListQueryBindingDTO,
    };
    use crate::error::{BindingError, ErrorResponseBindingDTO};
    use crate::test::TestContextWithOrganisation;

    #[tokio::test]
    async fn test_create_backup() {
        let TestContextWithOrganisation { core, data_dir, .. } =
            TestContextWithOrganisation::create().await;
        let backup_file_path = data_dir.random_file();

        let BackupCreateBindingDTO {
            file,
            unexportable,
            history_id,
        } = core
            .create_backup("password".to_string(), backup_file_path.to_owned())
            .await
            .unwrap();

        assert_eq!(file, backup_file_path);

        assert_eq!(unexportable.total_credentials, 0);
        assert_eq!(unexportable.total_identifiers, 0);
        assert_eq!(unexportable.total_dids, 0);
        assert_eq!(unexportable.total_keys, 0);
        assert!(unexportable.credentials.is_empty());
        assert!(unexportable.identifiers.is_empty());
        assert!(unexportable.dids.is_empty());
        assert!(unexportable.keys.is_empty());

        let history = core.get_history_entry(history_id).await.unwrap();
        assert_eq!(history.entity_type, HistoryEntityTypeBindingEnum::Backup);
        assert_eq!(history.action, HistoryActionBindingEnum::Created);
    }

    #[tokio::test]
    async fn test_backup_info() {
        let TestContextWithOrganisation { core, .. } = TestContextWithOrganisation::create().await;

        let info = core.backup_info().await.unwrap();

        assert_eq!(info.total_credentials, 0);
        assert_eq!(info.total_identifiers, 0);
        assert_eq!(info.total_dids, 0);
        assert_eq!(info.total_keys, 0);
        assert!(info.credentials.is_empty());
        assert!(info.identifiers.is_empty());
        assert!(info.dids.is_empty());
        assert!(info.keys.is_empty());
    }

    #[tokio::test]
    async fn test_unpack_backup_success() {
        let TestContextWithOrganisation { core, data_dir, .. } =
            TestContextWithOrganisation::create().await;

        let BackupCreateBindingDTO { file, .. } = core
            .create_backup("password".to_string(), data_dir.random_file())
            .await
            .unwrap();

        core.unpack_backup("password".to_string(), file)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_unpack_backup_wrong_password() {
        let TestContextWithOrganisation { core, data_dir, .. } =
            TestContextWithOrganisation::create().await;

        let BackupCreateBindingDTO { file, .. } = core
            .create_backup("password".to_string(), data_dir.random_file())
            .await
            .unwrap();

        let Err(BindingError::ErrorResponse {
            data: ErrorResponseBindingDTO { cause, .. },
        }) = core.unpack_backup("wrong".to_string(), file).await
        else {
            panic!("invalid result");
        };

        assert!(
            cause
                .clone()
                .unwrap()
                .message
                .contains("Failed to decrypt db file"),
            "cause = {cause:?}",
        );
    }

    #[tokio::test]
    async fn test_finalize_import() {
        let TestContextWithOrganisation {
            core,
            data_dir,
            organisation_id,
        } = TestContextWithOrganisation::create().await;

        let BackupCreateBindingDTO { file, .. } = core
            .create_backup("password".to_string(), data_dir.random_file())
            .await
            .unwrap();

        core.unpack_backup("password".to_string(), file)
            .await
            .unwrap();

        core.finalize_import().await.unwrap();

        let history = core
            .get_history_list(HistoryListQueryBindingDTO {
                page: 0,
                page_size: 1,
                organisation_id,
                entity_id: None,
                entity_types: Some(vec![HistoryEntityTypeBindingEnum::Backup]),
                actions: None,
                created_date_after: None,
                created_date_before: None,
                identifier_id: None,
                credential_id: None,
                credential_schema_id: None,
                proof_schema_id: None,
                search: None,
            })
            .await
            .unwrap();
        assert_eq!(
            history.values.first().unwrap().action,
            HistoryActionBindingEnum::Restored
        );
    }

    #[tokio::test]
    async fn test_rollback_import() {
        let TestContextWithOrganisation { core, data_dir, .. } =
            TestContextWithOrganisation::create().await;

        let BackupCreateBindingDTO { file, .. } = core
            .create_backup("password".to_string(), data_dir.random_file())
            .await
            .unwrap();

        core.unpack_backup("password".to_string(), file)
            .await
            .unwrap();

        core.rollback_import().await.unwrap();
    }
}

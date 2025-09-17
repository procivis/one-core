use std::path::PathBuf;
use std::sync::Arc;
use std::{env, fs};

use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::binding::OneCoreBinding;
use crate::binding::did::DidRequestKeysBindingDTO;
use crate::binding::identifier::{
    CreateIdentifierDidRequestBindingDTO, CreateIdentifierRequestBindingDTO,
};
use crate::binding::key::KeyRequestBindingDTO;
use crate::binding::organisation::CreateOrganisationRequestBindingDTO;
use crate::{InitParamsDTO, initialize};

/// Utility to create testing folder
/// - automatically cleaned-up in the end of the test (when dropped)
#[derive(Debug)]
pub(crate) struct TempDirContext {
    path: PathBuf,
}

impl TempDirContext {
    pub fn new() -> Self {
        let mut temp_dir = env::temp_dir();
        temp_dir.push(Uuid::new_v4().to_string());
        fs::create_dir(&temp_dir).unwrap();
        Self {
            path: temp_dir.as_path().to_owned(),
        }
    }

    pub fn path(&self) -> String {
        self.path.as_path().to_str().unwrap().to_owned()
    }

    /// gives full path to a random file inside the dir
    /// - does not create the file itself
    pub fn random_file(&self) -> String {
        let mut path = self.path.to_owned();
        path.push(Uuid::new_v4().to_string());
        path.as_path().to_str().unwrap().to_owned()
    }
}

impl Drop for TempDirContext {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

async fn initialize_core(data_dir_path: String) -> Arc<OneCoreBinding> {
    let additional_config = json!({
        "keyStorage": {
            "SECURE_ELEMENT": {
                "enabled": false
            },
            "INTERNAL": {
                "params": {
                    "private": {
                        "encryption": "93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e"
                    }
                }
            }
        },
        "issuanceProtocol": {
            "OPENID4VCI_DRAFT13": {
                "params": {
                    "private": {
                        "encryption": "93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e"
                    }
                }
            },
            "OPENID4VCI_DRAFT13_SWIYU": {
                "params": {
                    "private": {
                        "encryption": "93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e"
                    }
                }
            },
            "OPENID4VCI_FINAL1": {
                "params": {
                    "private": {
                        "encryption": "93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e"
                    }
                }
            }
        }
    })
    .to_string();

    initialize(
        data_dir_path,
        InitParamsDTO {
            config_json: Some(additional_config),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

pub struct TestContext {
    pub data_dir: TempDirContext,
    pub core: Arc<OneCoreBinding>,
}

impl TestContext {
    pub async fn create() -> Self {
        let data_dir = TempDirContext::new();
        let core = initialize_core(data_dir.path()).await;
        Self { data_dir, core }
    }
}

pub struct TestContextWithOrganisation {
    pub data_dir: TempDirContext,
    pub core: Arc<OneCoreBinding>,
    pub organisation_id: String,
}

impl TestContextWithOrganisation {
    pub async fn create() -> Self {
        let TestContext { core, data_dir } = TestContext::create().await;
        let organisation_id = core
            .create_organisation(CreateOrganisationRequestBindingDTO {
                id: None,
                name: None,
            })
            .await
            .unwrap();
        Self {
            data_dir,
            core,
            organisation_id,
        }
    }
}

#[tokio::test]
async fn test_initialize_core() {
    let data_dir = TempDirContext::new();
    initialize_core(data_dir.path()).await;
}

#[tokio::test]
async fn test_uninitialize_core_dont_delete_data() {
    let TestContextWithOrganisation {
        core,
        data_dir,
        organisation_id,
    } = TestContextWithOrganisation::create().await;

    let key_id = core
        .generate_key(KeyRequestBindingDTO {
            organisation_id: organisation_id.to_owned(),
            key_type: "ECDSA".to_string(),
            key_params: Default::default(),
            name: "test-key".to_string(),
            storage_type: "INTERNAL".to_string(),
            storage_params: Default::default(),
        })
        .await
        .unwrap();

    let identifier_id = core
        .create_identifier(CreateIdentifierRequestBindingDTO {
            organisation_id,
            name: "test-identifier".to_string(),
            key_id: None,
            did: Some(CreateIdentifierDidRequestBindingDTO {
                name: Some("test-did".to_string()),
                method: "KEY".to_string(),
                keys: DidRequestKeysBindingDTO {
                    authentication: vec![key_id.to_owned()],
                    assertion_method: vec![key_id.to_owned()],
                    key_agreement: vec![key_id.to_owned()],
                    capability_invocation: vec![key_id.to_owned()],
                    capability_delegation: vec![key_id],
                },
                params: Default::default(),
            }),
            certificates: None,
        })
        .await
        .unwrap();

    core.uninitialize(false).await.unwrap();

    let dir_content = fs::read_dir(data_dir.path()).unwrap();
    assert_eq!(dir_content.into_iter().count(), 1);

    let reinitialized_core = initialize_core(data_dir.path()).await;

    reinitialized_core
        .get_identifier(identifier_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_uninitialize_core_delete_data() {
    let TestContext { core, data_dir } = TestContext::create().await;

    core.uninitialize(true).await.unwrap();

    let dir_content = fs::read_dir(data_dir.path()).unwrap();
    assert_eq!(dir_content.into_iter().count(), 0);
}

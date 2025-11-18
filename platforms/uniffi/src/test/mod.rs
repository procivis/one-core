use std::path::PathBuf;
use std::sync::Arc;
use std::{env, fs};

use serde_json::json;
use uuid::Uuid;

use crate::binding::OneCoreBinding;
use crate::binding::organisation::CreateOrganisationRequestBindingDTO;
use crate::{InitParamsDTO, initialize};

mod initialize;
mod migration;

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

    /// creates a new file inside the temp dir with specified content
    pub fn create_file(&self, content: &[u8]) -> String {
        let file_path = self.random_file();
        fs::write(&file_path, content).unwrap();
        file_path
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
        "keySecurityLevel": {
            "MODERATE": {
                "enabled": false
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

use std::sync::Arc;

use super::Error;
use super::dto::{ImportCredentialSchemaRequestDTO, ImportCredentialSchemaV2RequestDTO};
use super::importer::CredentialSchemaImporter;
use super::parser::CredentialSchemaImportParser;
use crate::error::ContextWithErrorCode;
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::proto::http_client::HttpClient;
use crate::service::credential_schema::dto::{
    ImportCredentialSchemaRequestSchemaDTO, ImportCredentialSchemaV2RequestSchemaDTO,
};

/// Downloads a published credential schema and imports it.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait CredentialSchemaUrlImporter: Send + Sync {
    async fn import_credential_schema_from_url(
        &self,
        url: &str,
        organisation: Organisation,
    ) -> Result<CredentialSchema, Error>;
}

pub(crate) struct CredentialSchemaUrlImporterProto {
    client: Arc<dyn HttpClient>,
    parser: Arc<dyn CredentialSchemaImportParser>,
    importer: Arc<dyn CredentialSchemaImporter>,
}

impl CredentialSchemaUrlImporterProto {
    pub(crate) fn new(
        client: Arc<dyn HttpClient>,
        parser: Arc<dyn CredentialSchemaImportParser>,
        importer: Arc<dyn CredentialSchemaImporter>,
    ) -> Self {
        Self {
            client,
            parser,
            importer,
        }
    }
}

#[async_trait::async_trait]
impl CredentialSchemaUrlImporter for CredentialSchemaUrlImporterProto {
    async fn import_credential_schema_from_url(
        &self,
        url: &str,
        organisation: Organisation,
    ) -> Result<CredentialSchema, Error> {
        let response = async { self.client.get(url).send().await?.error_for_status() }
            .await
            .error_while("fetching credential schema")?;

        let credential_schema = if is_v2_credential_schema_url(url) {
            let import_request: ImportCredentialSchemaV2RequestSchemaDTO = response
                .json()
                .error_while("parsing fetched credential schema")?;
            self.parser
                .parse_import_credential_schema_v2(ImportCredentialSchemaV2RequestDTO {
                    organisation,
                    schema: import_request.into(),
                })
                .error_while("parsing credential schema")?
        } else {
            let import_request: ImportCredentialSchemaRequestSchemaDTO = response
                .json()
                .error_while("parsing fetched credential schema")?;
            self.parser
                .parse_import_credential_schema(ImportCredentialSchemaRequestDTO {
                    organisation,
                    schema: import_request.into(),
                })
                .error_while("parsing credential schema")?
        };

        Ok(self
            .importer
            .import_credential_schema(credential_schema)
            .await
            .error_while("importing credential schema")?)
    }
}

fn is_v2_credential_schema_url(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .is_some_and(|u| u.path().contains("/ssi/schema/v2/"))
}

#[cfg(test)]
mod tests {
    use super::is_v2_credential_schema_url;

    #[test]
    fn v2_credential_schema_url_detection() {
        assert!(is_v2_credential_schema_url(
            "https://example.com/ssi/schema/v2/abcd"
        ));
        assert!(!is_v2_credential_schema_url(
            "https://example.com/ssi/schema/v1/abcd"
        ));
        assert!(!is_v2_credential_schema_url("not a url"));
    }
}

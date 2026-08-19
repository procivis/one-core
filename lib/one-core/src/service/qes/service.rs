use shared_types::OrganisationId;
use uuid::Uuid;

use super::QesService;
use super::dto::{
    QesAuthorizeRequestDTO, QesAuthorizeResponseDTO, QesSignRequestDTO, QesSignResponseDTO,
};
use super::error::QesError;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::proto::session_provider::SessionExt;
use crate::provider::document_signer::DocumentSigner;
use crate::provider::document_signer::model::{AuthorizationRequest, SignRequest};
use crate::service::error::ServiceError;

impl QesService {
    pub async fn authorize(
        &self,
        request: QesAuthorizeRequestDTO,
    ) -> Result<QesAuthorizeResponseDTO, ServiceError> {
        let signer = self.resolve(&request.provider)?;

        let authorization = signer
            .get_authorization_request(AuthorizationRequest {
                document: request.document,
                redirect_uri: request.redirect_uri,
            })
            .await
            .error_while("building qes authorization request")?;

        Ok(QesAuthorizeResponseDTO {
            authorization_url: authorization.authorization_url,
            code_verifier: authorization.code_verifier,
        })
    }

    pub async fn sign(
        &self,
        request: QesSignRequestDTO,
    ) -> Result<QesSignResponseDTO, ServiceError> {
        let signer = self.resolve(&request.provider)?;

        let signed = signer
            .sign(SignRequest {
                code: request.code,
                code_verifier: request.code_verifier,
                redirect_uri: request.redirect_uri,
                document: request.document,
            })
            .await
            .error_while("signing document")?;

        self.write_signed_history(request.organisation_id).await;

        Ok(QesSignResponseDTO {
            signed_document: signed.content,
        })
    }

    async fn write_signed_history(&self, organisation_id: Option<OrganisationId>) {
        let organisation_id = organisation_id.or_else(|| {
            self.session_provider
                .session()
                .and_then(|s| s.organisation_id)
        });
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action: HistoryAction::Signed,
                name: String::new(),
                source: HistorySource::Qtsp,
                target: None,
                entity_id: None,
                entity_type: HistoryEntityType::QesDocument,
                metadata: None,
                metadata_blob_id: None,
                organisation_id,
                user: self.session_provider.session().user(),
            })
            .await;
        if let Err(err) = result {
            tracing::warn!("Failed to write QES sign history: {err}");
        }
    }

    fn resolve(&self, provider: &str) -> Result<std::sync::Arc<dyn DocumentSigner>, ServiceError> {
        self.document_signer_provider.get(provider).map_err(|_| {
            QesError::ProviderNotFound(provider.to_string())
                .error_while("resolving document signer")
                .into()
        })
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use similar_asserts::assert_eq;

    use super::*;
    use crate::proto::session_provider::NoSessionProvider;
    use crate::provider::document_signer::MockDocumentSigner;
    use crate::provider::document_signer::model::{Authorization, SignedDocument};
    use crate::provider::document_signer::provider::MockDocumentSignerProvider;
    use crate::repository::history_repository::MockHistoryRepository;

    fn service_with(signer: MockDocumentSigner) -> QesService {
        let signer: Arc<dyn DocumentSigner> = Arc::new(signer);
        let mut provider = MockDocumentSignerProvider::new();
        provider.expect_get().returning(move |_| Ok(signer.clone()));
        let mut history = MockHistoryRepository::new();
        history
            .expect_create_history()
            .returning(|_| Ok(Uuid::new_v4().into()));
        QesService::new(
            Arc::new(provider),
            Arc::new(history),
            Arc::new(NoSessionProvider),
        )
    }

    fn pdf_bytes() -> Vec<u8> {
        b"%PDF-1.7 hello".to_vec()
    }

    #[tokio::test]
    async fn authorize_returns_url_and_verifier() {
        let mut signer = MockDocumentSigner::new();
        signer.expect_get_authorization_request().returning(|_| {
            Ok(Authorization {
                authorization_url: "https://auth.example/authorize?x=1".to_string(),
                code_verifier: "verifier-123".to_string(),
            })
        });

        let response = service_with(signer)
            .authorize(QesAuthorizeRequestDTO {
                provider: "SIGN8".to_string(),
                document: pdf_bytes(),
                redirect_uri: None,
                organisation_id: None,
            })
            .await
            .unwrap();

        assert_eq!(
            response.authorization_url,
            "https://auth.example/authorize?x=1"
        );
        assert_eq!(response.code_verifier, "verifier-123");
    }

    #[tokio::test]
    async fn sign_returns_signed_document() {
        let mut signer = MockDocumentSigner::new();
        signer.expect_sign().returning(|_| {
            Ok(SignedDocument {
                content: b"%PDF-signed".to_vec(),
            })
        });

        let response = service_with(signer)
            .sign(QesSignRequestDTO {
                provider: "SIGN8".to_string(),
                code: "c".to_string(),
                code_verifier: "v".to_string(),
                document: pdf_bytes(),
                redirect_uri: None,
                organisation_id: None,
            })
            .await
            .unwrap();

        assert_eq!(response.signed_document, b"%PDF-signed".to_vec());
    }

    #[tokio::test]
    async fn sign_writes_a_qtsp_signed_history_event() {
        let mut signer = MockDocumentSigner::new();
        signer.expect_sign().returning(|_| {
            Ok(SignedDocument {
                content: b"signed".to_vec(),
            })
        });
        let signer: Arc<dyn DocumentSigner> = Arc::new(signer);

        let mut provider = MockDocumentSignerProvider::new();
        provider.expect_get().returning(move |_| Ok(signer.clone()));

        let mut history = MockHistoryRepository::new();
        history
            .expect_create_history()
            .withf(|event| {
                event.entity_type == HistoryEntityType::QesDocument
                    && event.source == HistorySource::Qtsp
                    && event.action == HistoryAction::Signed
                    && event.name.is_empty()
                    && event.entity_id.is_none()
            })
            .returning(|_| Ok(Uuid::new_v4().into()));

        let service = QesService::new(
            Arc::new(provider),
            Arc::new(history),
            Arc::new(NoSessionProvider),
        );

        service
            .sign(QesSignRequestDTO {
                provider: "SIGN8".to_string(),
                code: "c".to_string(),
                code_verifier: "v".to_string(),
                document: pdf_bytes(),
                redirect_uri: None,
                organisation_id: None,
            })
            .await
            .unwrap();
    }
}

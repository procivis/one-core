use crate::{
    data_layer::DataLayerError,
    data_model::{ConnectVerifierRequest, ConnectVerifierResponse},
    error::OneCoreError,
    OneCore,
};

impl OneCore {
    pub async fn verifier_connect(
        &self,
        _transport_protocol: &str,
        _request: &ConnectVerifierRequest,
    ) -> Result<ConnectVerifierResponse, OneCoreError> {
        // TODO: implement state validation, did insertion + proof update
        Err(OneCoreError::DataLayerError(
            DataLayerError::GeneralRuntimeError("Verifier-connect not yet implemented".to_owned()),
        ))
    }
}

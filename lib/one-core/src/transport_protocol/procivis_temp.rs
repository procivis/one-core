use super::{TransportProtocol, TransportProtocolError};

pub struct ProcivisTemp {}

impl TransportProtocol for ProcivisTemp {
    fn send(&self, _input: &str) -> Result<(), TransportProtocolError> {
        Ok(())
    }
    fn handle_message(&self, _message: &str) -> Result<(), TransportProtocolError> {
        Ok(())
    }
}

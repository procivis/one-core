pub mod procivis_temp;

#[derive(Debug)]
pub enum TransportProtocolError {
    Failed(String),
}

// This is just a proposition.
// Will be  developed in future.
pub trait TransportProtocol {
    fn send(&self, input: &str) -> Result<(), TransportProtocolError>;
    fn handle_message(&self, message: &str) -> Result<(), TransportProtocolError>;
}

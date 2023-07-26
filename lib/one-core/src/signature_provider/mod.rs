// This is just a proposition.
// Will be  developed in future.
pub trait SignatureProvider {
    fn sign(&self, input: &str) -> String;
    fn verify(&self, input: &str) -> bool;
}

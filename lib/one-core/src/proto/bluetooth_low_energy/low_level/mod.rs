pub mod ble_central;
pub mod ble_peripheral;
pub mod dto;

// ISO 18013-5, 8.3.3.1.1.6
// we need to send data bellow the agreed MTU since on some devices the header overhead is part of the negotiated MTU
pub const MTU_HEADER_OVERHEAD: u16 = 3;

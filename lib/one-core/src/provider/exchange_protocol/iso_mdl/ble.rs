use std::sync::LazyLock;

use uuid::Uuid;

// BLE peripheral server mode characteristics
pub(crate) const STATE: &str = "00000001-A123-48CE-896B-4C76973373E6";
pub(crate) const CLIENT_2_SERVER: &str = "00000002-A123-48CE-896B-4C76973373E6";
pub(crate) const SERVER_2_CLIENT: &str = "00000003-A123-48CE-896B-4C76973373E6";

// Shared BleWaiter flowId for both verifier and holder
pub(crate) static ISO_MDL_FLOW: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

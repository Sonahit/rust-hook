use serde_json::Value;
/**
   TCP HOOK PROTOCOL
   0 - 4 HOOK IDENTITY BYTES
   4 - 8  VERSION
   8 - 16 HOOK TYPE
   16 - * DATA
*/
use std::str::from_utf8;

pub const IDENTITY_BYTES: &[u8] = &[0x99, 0x99, 0x99, 0x99];
pub const IDENTITY_BYTES_LENGTH: usize = IDENTITY_BYTES.len();
pub const VERSION_BYTES: usize = 1 << 2;
pub const VERSION: &str = "v1";
pub const HOOK_TYPE_BYTES: usize = 1 << 3;
pub const HOOK_TYPE: &str = "v1";

pub const HOOK_PORT: usize = 7070;

#[derive(Debug)]
pub struct HookProtocol<T> {
    pub version: String,
    pub hook_type: String,
    pub bytes: Vec<u8>,
    pub data: T,
}

impl HookProtocol<Value> {
    /**
     * Create hook protocol entity from incoming bytes
     * Bytes should have [99, 99, 99, 99] identity bytes otherwise it will panic
     */
    pub fn new(bytes: Vec<u8>) -> Self {
        let bytes_iter = bytes.iter();
        let identity_bytes = bytes_iter
            .clone()
            .take(IDENTITY_BYTES_LENGTH)
            .copied()
            .collect::<Vec<u8>>();
        assert_eq!(&identity_bytes, IDENTITY_BYTES);

        let version_bytes = bytes_iter
            .clone()
            .skip(IDENTITY_BYTES_LENGTH)
            .take(VERSION_BYTES)
            .copied()
            .filter(|v| v != &0x0)
            .collect::<Vec<u8>>();
        let hook_type_bytes = bytes_iter
            .clone()
            .skip(VERSION_BYTES + IDENTITY_BYTES_LENGTH)
            .take(HOOK_TYPE_BYTES)
            .copied()
            .filter(|v| v != &0x0)
            .collect::<Vec<u8>>();

        let data_bytes = bytes_iter
            .clone()
            .skip(VERSION_BYTES + HOOK_TYPE_BYTES + IDENTITY_BYTES_LENGTH)
            .copied()
            .filter(|v| v != &0x0)
            .collect::<Vec<u8>>();
        let version = String::from(from_utf8(&version_bytes).unwrap());
        let hook_type = String::from(from_utf8(&hook_type_bytes).unwrap());

        HookProtocol {
            version,
            hook_type,
            bytes: data_bytes.clone(),
            data: serde_json::from_slice(&data_bytes.clone()).unwrap(),
        }
    }

    /**
     * Check if bytes has identification bytes
     */
    pub fn is_hook_protocol(bytes: Vec<u8>) -> bool {
        let bytes_iter = bytes.iter();
        let identity_bytes = bytes_iter
            .clone()
            .take(IDENTITY_BYTES_LENGTH)
            .copied()
            .collect::<Vec<u8>>();
        identity_bytes
            .iter()
            .zip(IDENTITY_BYTES)
            .filter(|(a, b)| a == b)
            .count()
            == IDENTITY_BYTES_LENGTH
    }
}

#[cfg(test)]
mod test {

    fn create_bytes(initial: &[u8], len: u8) -> Vec<u8> {
        let mut zeros = vec![0; len as usize];
        zeros[..initial.len()].clone_from_slice(initial);
        zeros
    }

    #[test]
    fn it_can_parse_protocol() {
        let mut identity_bytes = create_bytes(super::IDENTITY_BYTES, 4);
        let mut version_bytes = create_bytes(b"v1", 4);
        let mut hook_type_bytes = create_bytes(b"default", 8);
        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut identity_bytes);
        bytes.append(&mut version_bytes);
        bytes.append(&mut hook_type_bytes);
        let protocol = super::HookProtocol::new(bytes);
        assert_eq!(String::from("default"), protocol.hook_type);
        assert_eq!(String::from("v1"), protocol.version);
    }

    #[test]
    fn it_should_panics() {
        let mut version_bytes = create_bytes(b"v1", 4);
        let mut hook_type_bytes = create_bytes(b"default", 8);
        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut version_bytes);
        bytes.append(&mut hook_type_bytes);
        let result = std::panic::catch_unwind(|| super::HookProtocol::new(bytes));
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn should_have_empty_version_and_data() {
        let mut identity_bytes = create_bytes(super::IDENTITY_BYTES, 4);
        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut identity_bytes);
        let protocol = super::HookProtocol::new(bytes);
        let empty_string = String::from("");
        assert_eq!(empty_string, protocol.hook_type);
        assert_eq!(empty_string, protocol.version);
        assert_eq!(protocol.data, vec![]);
    }

    #[test]
    fn it_should_be_protocol() {
        let mut identity_bytes = create_bytes(super::IDENTITY_BYTES, 4);
        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut identity_bytes);
        assert_eq!(super::HookProtocol::is_hook_protocol(bytes), true);
    }

    #[test]
    fn it_should_not_be_protocol() {
        let mut identity_bytes = create_bytes(&[99, 99], 2);
        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut identity_bytes);
        assert_eq!(false, super::HookProtocol::is_hook_protocol(bytes));
    }
}

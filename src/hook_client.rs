use serde_json::Value;
use std::io::Write;
use std::net;

use crate::hook_prot as hook_protocol;

pub struct HookClient {
    pub dest: net::SocketAddr,
}

pub struct HookPacket<T> {
    pub data: T,
    inner_data: Vec<u8>,
}

fn create_bytes(initial: &[u8], len: u8) -> Vec<u8> {
    let mut zeros = vec![0; len as usize];
    zeros[..initial.len()].clone_from_slice(initial);
    zeros
}

impl HookPacket<serde_json::Value> {
    pub fn new(version: &str, hook_type: &str, data: Value) -> Self {
        let mut first_bytes = hook_protocol::IDENTITY_BYTES.to_vec();
        let mut version_bytes =
            create_bytes(version.as_bytes(), hook_protocol::VERSION_BYTES as u8);
        let mut hook_type_bytes =
            create_bytes(hook_type.as_bytes(), hook_protocol::HOOK_TYPE_BYTES as u8);
        let mut inner_data: Vec<u8> = Vec::new();
        inner_data.append(&mut first_bytes);
        inner_data.append(&mut version_bytes);
        inner_data.append(&mut hook_type_bytes);
        inner_data.append(&mut format!("{}", data).as_bytes().to_vec());
        HookPacket { data, inner_data }
    }
}

impl HookPacket<String> {
    pub fn new(version: &str, hook_type: &str, data: String) -> Self {
        let mut first_bytes = hook_protocol::IDENTITY_BYTES.to_vec();
        let mut version_bytes =
            create_bytes(version.as_bytes(), hook_protocol::VERSION_BYTES as u8);
        let mut hook_type_bytes =
            create_bytes(hook_type.as_bytes(), hook_protocol::HOOK_TYPE_BYTES as u8);
        let mut inner_data: Vec<u8> = Vec::new();
        inner_data.append(&mut first_bytes);
        inner_data.append(&mut version_bytes);
        inner_data.append(&mut hook_type_bytes);
        inner_data.append(&mut data.as_bytes().to_vec());
        HookPacket { data, inner_data }
    }
}

impl HookClient {
    pub fn new(dest: net::SocketAddr) -> Self {
        HookClient { dest }
    }
    pub fn send<T>(&self, packet: HookPacket<T>) -> std::io::Result<usize> {
        let socket = net::TcpStream::connect(self.dest);
        match socket {
            Ok(mut socket) => socket.write(&packet.inner_data),
            Err(err) => Err(err),
        }
    }
}

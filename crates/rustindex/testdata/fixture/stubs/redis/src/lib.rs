//! Surface-only stub of redis: a connection with get/set, enough for the G1
//! cache-client monikers.

pub struct Connection;

impl Connection {
    pub fn get(&mut self, _key: &str) -> String {
        String::new()
    }
    pub fn set(&mut self, _key: &str, _value: &str) {}
}

pub struct Client;

impl Client {
    pub fn open(_url: &str) -> Client {
        Client
    }
    pub fn get_connection(&self) -> Connection {
        Connection
    }
}

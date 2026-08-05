//! Surface-only stub of reqwest: just enough shape for rust-analyzer to
//! resolve the monikers the fixture app exercises. No I/O, no deps.

pub struct Client;
pub struct ClientBuilder;
pub struct RequestBuilder;
pub struct Response;
#[derive(Debug)]
pub struct Error;

impl Client {
    pub fn new() -> Client {
        Client
    }
    pub fn builder() -> ClientBuilder {
        ClientBuilder
    }
    pub fn get(&self, _url: &str) -> RequestBuilder {
        RequestBuilder
    }
    pub fn post(&self, _url: &str) -> RequestBuilder {
        RequestBuilder
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

impl ClientBuilder {
    pub fn timeout(self, _d: core::time::Duration) -> ClientBuilder {
        self
    }
    pub fn build(self) -> Result<Client, Error> {
        Ok(Client)
    }
}

impl RequestBuilder {
    pub fn timeout(self, _d: core::time::Duration) -> RequestBuilder {
        self
    }
    #[allow(clippy::unused_async)]
    pub async fn send(self) -> Result<Response, Error> {
        Ok(Response)
    }
}

use hyper;
use hyper::client::response::Response;

pub trait WhoisHttpClient {
    fn get_content(&self, url: &str) -> hyper::Result<Response>;
}

#[derive(Debug)]
pub struct StdWhoisHttpClient {
    client: hyper::Client,
}

impl StdWhoisHttpClient {
    pub fn new() -> StdWhoisHttpClient {
        StdWhoisHttpClient { client: hyper::Client::new() }
    }
}

impl WhoisHttpClient for StdWhoisHttpClient {
    fn get_content(&self, url: &str) -> hyper::Result<Response> {
        let response = self.client
            .get(url)
            .send()?;
        Ok(response)
    }
}
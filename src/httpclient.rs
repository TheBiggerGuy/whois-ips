use std::fmt;
use std::result::Result::{self, Ok, Err};

use hyper;
use hyper::client::response::Response;
use hyper::status::StatusCode;

#[derive(Debug)]
#[derive(PartialEq)]
pub enum HttpClientError {
    HttpError(String),
    Unknown(String),
}

impl fmt::Display for HttpClientError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HttpClientError::HttpError(ref expr) => write!(fmt, "{}", expr),
            HttpClientError::Unknown(ref expr) => write!(fmt, "{}", expr),  
        }
    }
}

pub trait WhoisHttpClient {
    fn get_content(&self, url: &str) -> Result<Response, HttpClientError>;
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
    fn get_content(&self, url: &str) -> Result<Response, HttpClientError> {
        let response = self.client
            .get(url)
            .send()
            .map_err(|e| HttpClientError::Unknown(format!("{}", e)))?;
        if response.status != StatusCode::Ok {
            return Err(HttpClientError::HttpError(format!("HTTP Error: {}", response.status)));
        }
        Ok(response)
    }
}

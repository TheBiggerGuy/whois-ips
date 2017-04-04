#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use]
extern crate clap;
extern crate iprange;
extern crate hyper;
extern crate xml;

use std::result::Result::{self, Ok};
use std::net::IpAddr;

use clap::{Arg, App};

use iprange::IpAddrRange;

mod httpclient;
use httpclient::{WhoisHttpClient, StdWhoisHttpClient};

mod xmlparser;
use xmlparser::{WhoisXmlParser, StdWhoisXmlParser};


#[derive(Debug)]
pub struct WhoisIpResult {
    name: String,
    start_ip: IpAddr,
    end_ip: IpAddr,
}

#[derive(Debug)]
pub struct WhoisResult {
    ips: Vec<WhoisIpResult>,
}

impl WhoisResult {
    fn new(ips: Vec<WhoisIpResult>) -> WhoisResult {
        WhoisResult { ips: ips }
    }
}


struct WhoisCompanyIpsClient<C: WhoisHttpClient, P: WhoisXmlParser> {
    client: C,
    parser: P,
}

impl WhoisCompanyIpsClient<StdWhoisHttpClient, StdWhoisXmlParser> {
    fn new() -> WhoisCompanyIpsClient<StdWhoisHttpClient, StdWhoisXmlParser> {
        WhoisCompanyIpsClient {
            client: StdWhoisHttpClient::new(),
            parser: StdWhoisXmlParser::new(),
        }
    }

    fn get(&self, company: &str) -> Result<WhoisResult, String> {
        let url = format!("http://whois.arin.net/rest/org/{}/nets", company);
        let http_response = self.client.get_content(&url);
        if http_response.is_err() {
            return Err(format!("HTTP Error: {:}", http_response.unwrap_err()));
        }
        let parsed_response = self.parser.parse_content(http_response.unwrap());
        if parsed_response.is_err() {
            return Err(format!("XML Error: {:}", parsed_response.unwrap_err()));
        }
        Ok(parsed_response.unwrap())
    }
}

// https://www.arin.net/resources/whoisrws/whois_api.html
fn main() {
    let cmd_line_args = App::new("myapp")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Look up assigned IPv4/6 address ranges by company name")
        .arg(Arg::with_name("COMPANY").required(true).takes_value(true))
        .get_matches_safe()
        .unwrap_or_else(|e| e.exit());

    let company_name = cmd_line_args.value_of("COMPANY").unwrap();

    let client = WhoisCompanyIpsClient::new();
    let response = client.get(company_name);

    if response.is_err() {
        println!("{:}", response.unwrap_err());
        return
    }

    for ip in response.unwrap().ips {
        let range = IpAddrRange::from_range(ip.start_ip, ip.end_ip);
        println!("{}", range.unwrap());
    }
}


#[cfg(test)]
mod tests {
}

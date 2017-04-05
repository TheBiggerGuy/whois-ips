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

    fn url_from_filter(filter: &Filter) -> String {
        match *filter {
            Filter::PointOfContact(ref poc) => {
                format!("http://whois.arin.net/rest/poc/{}/nets?showDetails=true", poc)
            }
            Filter::Organization(ref org) => format!("http://whois.arin.net/rest/org/{}/nets?showDetails=true", org),
        }
    }

    fn get(&self, filter: &Filter) -> Result<WhoisResult, String> {
        let url = WhoisCompanyIpsClient::url_from_filter(&filter);
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

enum Filter {
    PointOfContact(String),
    Organization(String),
}

// https://www.arin.net/resources/whoisrws/whois_api.html
fn main() {
    let cmd_line_args = App::new("myapp")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Look up assigned IPv4/6 address ranges from ARIN")
        .arg(Arg::with_name("POINT_OF_CONTACT")
                 .short("p")
                 .required_unless("ORGANIZATION")
                 .takes_value(true)
                 .conflicts_with("ORGANIZATION"))
        .arg(Arg::with_name("ORGANIZATION")
                 .short("o")
                 .required_unless("POINT_OF_CONTACT")
                 .takes_value(true)
                 .conflicts_with("POINT_OF_CONTACT"))
        .get_matches_safe()
        .unwrap_or_else(|e| e.exit());

    let cmd_line_poc = cmd_line_args.value_of("POINT_OF_CONTACT");
    let filter = match cmd_line_poc {
        Some(poc) => Filter::PointOfContact(poc.to_string()),
        None => Filter::Organization(cmd_line_args.value_of("ORGANIZATION").unwrap().to_string()),
    };

    let client = WhoisCompanyIpsClient::new();
    let response = client.get(&filter);

    if response.is_err() {
        println!("{:}", response.unwrap_err());
        return;
    }

    for ip in response.unwrap().ips {
        let range = IpAddrRange::from_range(ip.start_ip, ip.end_ip);
        println!("{}", range.unwrap());
    }
}


#[cfg(test)]
mod tests {}

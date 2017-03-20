#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

extern crate hyper;
extern crate xml;
extern crate iprange;

use std::result::Result;
use std::result::Result::Ok;
use std::option::Option;
use std::io;
use std::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hyper::client::response::Response;

use xml::reader::{EventReader, XmlEvent};
use xml::attribute::OwnedAttribute;

use iprange::IpAddrRange;


#[derive(Debug)]
struct WhoisIpResult {
    name: String,
    start_ip: IpAddr,
    end_ip: IpAddr,
}

#[derive(Debug)]
struct WhoisResult {
    ips: Vec<WhoisIpResult>
}

impl WhoisResult {
    fn new(ips: Vec<WhoisIpResult>) -> WhoisResult {
        WhoisResult { 
            ips: ips,
        }
    }
}

trait WhoisHttpClient {
    fn get_content(&self, url: &str) -> hyper::Result<Response>;
}

#[derive(Debug)]
#[derive(PartialEq)]
enum ParseError {
    XmlError(xml::reader::Error),
    LimitExceeded,
}

trait WhoisXmlParser {
    fn parse_content<T: io::Read>(&self, xml: T) -> Result<WhoisResult, ParseError>;
}

#[derive(Debug)]
struct StdWhoisHttpClient {
    client: hyper::Client,
}

impl StdWhoisHttpClient {
    fn new() -> StdWhoisHttpClient {
        StdWhoisHttpClient {
            client: hyper::Client::new(),
        }
    }
}

impl WhoisHttpClient for StdWhoisHttpClient {
    fn get_content(&self, url: &str) -> hyper::Result<Response> {
        let response = self.client.get(url).send()?;
        Ok(response)
    }
}

#[derive(Debug)]
struct StdWhoisXmlParser {
}

impl StdWhoisXmlParser {
    fn new() -> StdWhoisXmlParser {
        StdWhoisXmlParser {}
    }

    fn parse_content_netref(attributes: Vec<OwnedAttribute>) -> Result<WhoisIpResult, xml::reader::Error> {
        let mut range_name : Option<String> = Option::None;
        let mut start_ip : Option<IpAddr> = Option::None;
        let mut end_ip : Option<IpAddr> = Option::None;

        for attribute in attributes {
            match attribute.name.local_name.as_ref() {
                "name" => {
                    range_name = Option::Some(attribute.value.clone());
                },
                "startAddress" => {
                    start_ip = Option::Some(IpAddr::from_str(&attribute.value).unwrap());
                },
                "endAddress" => {
                    end_ip = Option::Some(IpAddr::from_str(&attribute.value).unwrap());
                }
                _ => { }
            }
        }
        
        Ok(WhoisIpResult {
            name: range_name.unwrap(),
            start_ip: start_ip.unwrap(),
            end_ip: end_ip.unwrap()
        })
    }
}

impl WhoisXmlParser for StdWhoisXmlParser {
    fn parse_content<T: io::Read>(&self, xml: T) -> Result<WhoisResult, ParseError> {
        let mut ip_results : Vec<WhoisIpResult> = Vec::new();
        
        let parser = EventReader::new(xml);
        let mut is_inside_limit = false;
        for elm in parser {
            match elm {
                Ok(XmlEvent::StartElement{ name, attributes, .. }) => {
                    match name.local_name.as_ref() {
                        "netRef" => {
                            let ip_result = StdWhoisXmlParser::parse_content_netref(attributes);
                            ip_results.push(ip_result.unwrap());
                        },
                        "limitExceeded" => {
                            is_inside_limit = true;
                        }
                        _ => { }
                    } 
                },
                Ok(XmlEvent::Characters(s)) => {
                    if is_inside_limit {
                        match  s.as_ref() {
                            "false" => { },
                            _ => {
                                return Err(ParseError::LimitExceeded);
                            }
                        }
                    }
                }
                Ok(XmlEvent::EndElement{ .. }) => {
                    is_inside_limit = false;
                },
                Ok(XmlEvent::CData(_)) => {
                    panic!("XML parser returned CData. This should never happen");
                },
                Err(e) => {
                    return Err(ParseError::XmlError(e));
                },
                _ => { }
            }
        }

        Ok(WhoisResult::new(ip_results))
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
            return Err("Fail".to_string())
        }
        let parsed_response = self.parser.parse_content(http_response.unwrap());
        if parsed_response.is_err() {
            return Err("Fail".to_string())
        }
        Ok(parsed_response.unwrap())
    }
}

// https://www.arin.net/resources/whoisrws/whois_api.html
fn main() {
    let client = WhoisCompanyIpsClient::new();
    let response = client.get("DROPB");

    println!("================================================================================");
    println!("{:?}", response);
    println!("================================================================================");
    for ip in response.unwrap().ips {
        let range = IpAddrRange::from_range(ip.start_ip, ip.end_ip);
        println!("{:?}", range);
    }
    println!("================================================================================");
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::net::IpAddr;

    use super::WhoisXmlParser;
    use super::StdWhoisXmlParser;
    use super::ParseError;

    #[test]
    #[ignore]
    fn parse_content_empty() {
        let xml = "".as_bytes();
        let result = StdWhoisXmlParser::new().parse_content(xml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_content_empty_xml() {
        let xml = r#"<?xml version="1.0"?>
<?xml-stylesheet type='text/xsl' href='http://whois.arin.net/xsl/website.xsl' ?>
<nets xmlns="http://www.arin.net/whoisrws/core/v1" xmlns:ns2="http://www.arin.net/whoisrws/rdns/v1" xmlns:ns3="http://www.arin.net/whoisrws/netref/v2" inaccuracyReportUrl="https://www.arin.net/public/whoisinaccuracy/index.xhtml" termsOfUse="https://www.arin.net/whois_tou.html">
  <limitExceeded limit="256">false</limitExceeded>
</nets>
"#.as_bytes();
        let result = StdWhoisXmlParser::new().parse_content(xml);
        assert!(result.is_ok());
        let whois_result = result.unwrap();
        assert_eq!(whois_result.ips.len(), 0);
    }

        #[test]
    fn parse_content_single() {
        let xml = r#"<?xml version="1.0"?>
<?xml-stylesheet type='text/xsl' href='http://whois.arin.net/xsl/website.xsl' ?>
<nets xmlns="http://www.arin.net/whoisrws/core/v1" xmlns:ns2="http://www.arin.net/whoisrws/rdns/v1" xmlns:ns3="http://www.arin.net/whoisrws/netref/v2" inaccuracyReportUrl="https://www.arin.net/public/whoisinaccuracy/index.xhtml" termsOfUse="https://www.arin.net/whois_tou.html">
  <limitExceeded limit="256">false</limitExceeded>
  <netRef endAddress="162.125.255.255" startAddress="162.125.0.0" handle="NET-162-125-0-0-1" name="DROPB">https://whois.arin.net/rest/net/NET-162-125-0-0-1</netRef>
</nets>
"#.as_bytes();
        let result = StdWhoisXmlParser::new().parse_content(xml);
        assert!(result.is_ok());
        let whois_result = result.unwrap();
        assert_eq!(whois_result.ips.len(), 1);
        let whois_ip_result = whois_result.ips.get(0).unwrap();
        assert_eq!(whois_ip_result.name, String::from("DROPB"));
        println!("{:?}", "162.125.0.0".parse::<IpAddr>());
        assert_eq!(whois_ip_result.start_ip, IpAddr::from_str("162.125.0.0").unwrap());
        assert_eq!(whois_ip_result.end_ip, IpAddr::from_str("162.125.255.255").unwrap());
    }

            #[test]
    fn parse_content_linit_exceeded() {
        let xml = r#"<?xml version="1.0"?>
<?xml-stylesheet type='text/xsl' href='http://whois.arin.net/xsl/website.xsl' ?>
<nets xmlns="http://www.arin.net/whoisrws/core/v1" xmlns:ns2="http://www.arin.net/whoisrws/rdns/v1" xmlns:ns3="http://www.arin.net/whoisrws/netref/v2" inaccuracyReportUrl="https://www.arin.net/public/whoisinaccuracy/index.xhtml" termsOfUse="https://www.arin.net/whois_tou.html">
  <limitExceeded limit="256">true</limitExceeded>
</nets>
"#.as_bytes();
        let result = StdWhoisXmlParser::new().parse_content(xml);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParseError::LimitExceeded);;
    }
}
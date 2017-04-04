use std::net::IpAddr;
use std::io;
use std::str::FromStr;
use std::fmt;

use xml::reader::{EventReader, XmlEvent};
use xml::attribute::OwnedAttribute;

use super::{WhoisResult, WhoisIpResult};

#[derive(Debug)]
#[derive(PartialEq)]
pub enum ParseError {
    XmlError(String),
    IpAddrError(String),
    LimitExceeded,
}

impl fmt::Display for ParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::XmlError(ref expr) => write!(fmt, "{}", expr),
            ParseError::IpAddrError(ref expr) => write!(fmt, "{}", expr),
            ParseError::LimitExceeded => write!(fmt, "API result limit exceeded"),
        }
    }
}
pub trait WhoisXmlParser {
    fn parse_content<T: io::Read>(&self, xml: T) -> Result<WhoisResult, ParseError>;
}

#[derive(Debug)]
pub struct StdWhoisXmlParser {}

impl StdWhoisXmlParser {
    pub fn new() -> StdWhoisXmlParser {
        StdWhoisXmlParser {}
    }

    fn parse_ip(ip_str : &str) -> Result<IpAddr, ParseError> {
        IpAddr::from_str(ip_str).map_err(|e| ParseError::IpAddrError(format!("Failed to parse IP address: {:} ({:})", e, ip_str)))
    }

    fn parse_content_netref(attributes: Vec<OwnedAttribute>)
                            -> Result<WhoisIpResult, ParseError> {
        let mut range_name: Option<String> = Option::None;
        let mut start_ip: Option<IpAddr> = Option::None;
        let mut end_ip: Option<IpAddr> = Option::None;

        for attribute in attributes {
            match attribute.name.local_name.as_ref() {
                "name" => {
                    range_name = Option::Some(attribute.value.clone());
                }
                "startAddress" => {
                    let ip = StdWhoisXmlParser::parse_ip(&attribute.value)?;
                    start_ip = Option::Some(ip);
                }
                "endAddress" => {
                    let ip = StdWhoisXmlParser::parse_ip(&attribute.value)?;
                    end_ip = Option::Some(ip);
                }
                _ => {}
            }
        }

        Ok(WhoisIpResult {
               name: range_name.unwrap(),
               start_ip: start_ip.unwrap(),
               end_ip: end_ip.unwrap(),
           })
    }
}

impl WhoisXmlParser for StdWhoisXmlParser {
    fn parse_content<T: io::Read>(&self, xml: T) -> Result<WhoisResult, ParseError> {
        let mut ip_results: Vec<WhoisIpResult> = Vec::new();

        let parser = EventReader::new(xml);
        let mut is_inside_limit = false;
        for elm in parser {
            match elm {
                Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                    match name.local_name.as_ref() {
                        "netRef" => {
                            let ip_result = StdWhoisXmlParser::parse_content_netref(attributes)?;
                            ip_results.push(ip_result);
                        }
                        "limitExceeded" => {
                            is_inside_limit = true;
                        }
                        _ => {}
                    }
                }
                Ok(XmlEvent::Characters(s)) => {
                    if is_inside_limit {
                        match s.as_ref() {
                            "false" => {}
                            _ => {
                                return Err(ParseError::LimitExceeded);
                            }
                        }
                    }
                }
                Ok(XmlEvent::EndElement { .. }) => {
                    is_inside_limit = false;
                }
                Ok(XmlEvent::CData(_)) => {
                    panic!("XML parser returned CData. This should never happen");
                }
                Err(e) => {
                    return Err(ParseError::XmlError(e.to_string()));
                }
                _ => {}
            }
        }

        Ok(WhoisResult::new(ip_results))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::net::IpAddr;

    use super::WhoisXmlParser;
    use super::StdWhoisXmlParser;
    use super::ParseError;

    #[test]
    fn parse_content_empty() {
        let xml = "".as_bytes();
        let result = StdWhoisXmlParser::new().parse_content(xml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_content_invalid_xml() {
        let xml = "{}".as_bytes();
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
        assert_eq!(whois_ip_result.start_ip,
                   IpAddr::from_str("162.125.0.0").unwrap());
        assert_eq!(whois_ip_result.end_ip,
                   IpAddr::from_str("162.125.255.255").unwrap());
    }

    // TODO: add ipv6 data
    #[test]
    fn parse_content_ipv4_and_ipv6() {
        let xml = r#"<?xml version="1.0"?>
<?xml-stylesheet type='text/xsl' href='http://whois.arin.net/xsl/website.xsl' ?>
<nets xmlns="http://www.arin.net/whoisrws/core/v1" xmlns:ns2="http://www.arin.net/whoisrws/rdns/v1" xmlns:ns3="http://www.arin.net/whoisrws/netref/v2" inaccuracyReportUrl="https://www.arin.net/public/whoisinaccuracy/index.xhtml" termsOfUse="https://www.arin.net/whois_tou.html">
  <limitExceeded limit="256">false</limitExceeded>
  <netRef endAddress="162.125.255.255" startAddress="162.125.0.0" handle="NET-162-125-0-0-1" name="DROPB">https://whois.arin.net/rest/net/NET-162-125-0-0-1</netRef>
  <netRef endAddress="162.125.255.255" startAddress="162.125.0.0" handle="NET-162-125-0-0-1" name="DROPB">https://whois.arin.net/rest/net/NET-162-125-0-0-1</netRef>
</nets>
"#.as_bytes();
        let result = StdWhoisXmlParser::new().parse_content(xml);
        assert!(result.is_ok());
        let whois_result = result.unwrap();
        assert_eq!(whois_result.ips.len(), 2);

        let whois_ip_result_0 = whois_result.ips.get(0).unwrap();
        assert_eq!(whois_ip_result_0.name, String::from("DROPB"));
        assert_eq!(whois_ip_result_0.start_ip,
                   IpAddr::from_str("162.125.0.0").unwrap());
        assert_eq!(whois_ip_result_0.end_ip,
                   IpAddr::from_str("162.125.255.255").unwrap());

        let whois_ip_result_1 = whois_result.ips.get(1).unwrap();
        assert_eq!(whois_ip_result_1.name, String::from("DROPB"));
        assert_eq!(whois_ip_result_1.start_ip,
                   IpAddr::from_str("162.125.0.0").unwrap());
        assert_eq!(whois_ip_result_1.end_ip,
                   IpAddr::from_str("162.125.255.255").unwrap());
    }

    #[test]
    fn parse_content_invalid_ip() {
        let xml = r#"<?xml version="1.0"?>
<?xml-stylesheet type='text/xsl' href='http://whois.arin.net/xsl/website.xsl' ?>
<nets xmlns="http://www.arin.net/whoisrws/core/v1" xmlns:ns2="http://www.arin.net/whoisrws/rdns/v1" xmlns:ns3="http://www.arin.net/whoisrws/netref/v2" inaccuracyReportUrl="https://www.arin.net/public/whoisinaccuracy/index.xhtml" termsOfUse="https://www.arin.net/whois_tou.html">
  <limitExceeded limit="256">false</limitExceeded>
  <netRef endAddress="162.125.255.255" startAddress="dropbox.com" handle="NET-162-125-0-0-1" name="DROPB">https://whois.arin.net/rest/net/NET-162-125-0-0-1</netRef>
</nets>
"#.as_bytes();
        let result = StdWhoisXmlParser::new().parse_content(xml);
        assert!(result.is_err());
        // TODO: Match error type
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
        assert_eq!(result.unwrap_err(), ParseError::LimitExceeded);
    }
}

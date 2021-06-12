use bytes::Bytes;
use domain::base::ToDname;
use thiserror::Error;
use std::net::IpAddr;

#[derive(Error, Debug)]
pub enum DnsParseError {
    #[error("Packet unable to parse, possibly corrupted")]
    BadPacket(#[from] domain::base::octets::ShortBuf),
    #[error("Packet unable to parse, possibly corrupted")]
    ParseFailure(#[from] domain::base::octets::ParseError),
    #[error("Unable to parse packet question")]
    ParseQuestionFailure,
    #[error("Unable to parse packet answer for question type")]
    ParseAnswerFailure,
    #[error("Not DNS Response")]
    NotDnsResponse,
    #[error("Lookup failed")]
    LookupFailed,
    #[error("Temp general error")]
    GeneralError,
}

#[derive(Debug, PartialEq)]
pub struct DnsResponse {
    pub fqdn: domain::base::name::Dname<Bytes>,
    pub addresses: Vec<IpAddr>,
}


fn parse_dns_payload(
    packet: &[u8],
    logger: &slog::Logger,
) -> Result<DnsResponse, DnsParseError> {
    let parsed_message = domain::base::message::Message::from_octets(packet)?;

    // ToDo(matt9j) Eventually ignore non-answers.
    // let is_answer = parsed_message.header().opcode();

    // Only handle the common case of a single question due to ambiguity in the
    // current IETF standard ca. 2021.
    let question = parsed_message.first_question().ok_or(DnsParseError::ParseQuestionFailure)?;
    slog::debug!{logger, "parsed a DNS question {:?}", question}
    let query = question.qname();

    let mut current_canonical_name = query.clone();

    // Parse all available answers and add them to the answer list.
    let answer_section = parsed_message.answer()?;
    let mut answer_addresses: Vec<IpAddr> = Vec::with_capacity(10);
    for a in answer_section.limit_to_in::<domain::rdata::AllRecordData<_, _>>() {
        let answer = a?;
        slog::debug!{logger, "parsed DNS answer {:?}", answer};
        if answer.owner().ne(&current_canonical_name) {
            continue;
        }

        match answer.data() {
            domain::rdata::AllRecordData::A(parsed_answer) => {
                answer_addresses.push(IpAddr::V4(parsed_answer.addr()));
            }
            domain::rdata::AllRecordData::Aaaa(parsed_answer) => {
                answer_addresses.push(IpAddr::V6(parsed_answer.addr()));
            }
            domain::rdata::AllRecordData::Cname(parsed_answer) => {
                current_canonical_name = parsed_answer.cname().clone();
                slog::debug!{logger, "parsed DNS answer {:?}", parsed_answer};
            }
            _ => {
                continue;
            }
        }
    }

    return Ok(DnsResponse {
        fqdn: query.to_bytes(),
        addresses: answer_addresses
    });
}


#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{parse_dns_payload, DnsParseError, DnsResponse};

    const TEST_DNS_AAAA_PAYLOAD: &str = "e5428180000100040000000004786b636403636f6d00001c0001c00c001c00010000065800102a044e42000000000000000000000067c00c001c00010000065800102a044e42020000000000000000000067c00c001c00010000065800102a044e42040000000000000000000067c00c001c00010000065800102a044e42060000000000000000000067";
    const TEST_DNS_A_PAYLOAD: &str = "c87f8180000100040000000004786b636403636f6d0000010001c00c0001000100000c97000497650043c00c0001000100000c97000497654043c00c0001000100000c97000497658043c00c0001000100000c9700049765c043";
    const TEST_DNS_CNAME_PAYLOAD: &str = "9af181800001000400000000046f6373700a676c6f62616c7369676e03636f6d0000010001c00c000500010000545d001106676c6f62616c037072640363646ec011c0310005000100000333002a0363646e0d676c6f62616c7369676e63646e03636f6d0363646e0a636c6f7564666c617265036e657400c04e000100010000012b0004681215e2c04e000100010000012b0004681214e2";
    const TEST_DNS_BROKEN_PAYLOAD: &str = "9af181800001000400000000046f637370";

    fn decode_hex(input: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..input.len()).step_by(2).map(|chunk_i| u8::from_str_radix(&input[chunk_i..chunk_i+2], 16)).collect()
    }

    fn make_logger() -> slog::Logger {
        use slog::*;
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        slog::Logger::root(drain, o!())
    }

    #[test]
    fn test_parse_dns_a_response() {
        let log = make_logger();
        let data = decode_hex(TEST_DNS_A_PAYLOAD).unwrap();
        let expected_result = DnsResponse {
            fqdn: domain::base::name::Dname::from_chars("xkcd.com.".chars()).unwrap(),
            addresses: vec![
                "151.101.0.67".parse().unwrap(),
                "151.101.64.67".parse().unwrap(),
                "151.101.128.67".parse().unwrap(),
                "151.101.192.67".parse().unwrap(),
            ]
        };
        assert_eq!(parse_dns_payload(&data, &log).unwrap(), expected_result);
    }

    #[test]
    fn test_parse_dns_aaaa_response() {
        let log = make_logger();
        let data = decode_hex(TEST_DNS_AAAA_PAYLOAD).unwrap();
        let expected_result = DnsResponse {
            fqdn: domain::base::name::Dname::from_chars("xkcd.com.".chars()).unwrap(),
            addresses: vec![
                "2a04:4e42::67".parse().unwrap(),
                "2a04:4e42:200::67".parse().unwrap(),
                "2a04:4e42:400::67".parse().unwrap(),
                "2a04:4e42:600::67".parse().unwrap(),
            ]
        };
        assert_eq!(parse_dns_payload(&data, &log).unwrap(), expected_result);
    }

    #[test]
    fn test_parse_dns_cname_response() {
        let log = make_logger();
        let data = decode_hex(TEST_DNS_CNAME_PAYLOAD).unwrap();
        let expected_result = DnsResponse {
            fqdn: domain::base::name::Dname::from_chars("ocsp.globalsign.com.".chars()).unwrap(),
            addresses: vec![
                "104.18.21.226".parse().unwrap(),
                "104.18.20.226".parse().unwrap(),
            ]
        };
        assert_eq!(parse_dns_payload(&data, &log).unwrap(), expected_result);
    }

    #[test]
    fn test_parse_dns_broken_response() {
        let log = make_logger();
        let data = decode_hex(TEST_DNS_BROKEN_PAYLOAD).unwrap();
        let result = parse_dns_payload(&data, &log).unwrap_err().to_string();
        let expected_error: Result<DnsResponse, DnsParseError> = Err(DnsParseError::ParseQuestionFailure);
        assert_eq!(result, expected_error.unwrap_err().to_string());
    }
}
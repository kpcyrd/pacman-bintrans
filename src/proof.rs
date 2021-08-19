use crate::errors::*;
use crate::http;
use blake2::{Blake2b, Digest};
use data_encoding::{Specification, Encoding};
use der_parser::oid::Oid;
use std::io::Cursor;
use x509_parser::parse_x509_der;
use x509_parser::pem::{pem_to_der, Pem};
use der_parser::ber::BerObjectContent;
use nom::IResult;
use nom::number::complete::be_u16;
use nom::bytes::complete::take;

// https://tools.ietf.org/html/rfc6962

const PROOF_SIZE_LIMIT: usize = 1024 * 1024; // 1M
const TRANS_PROOF_ID_LENGTH: usize = 12;
const HASH_SIZE: usize = 32; // 256bit

fn base32hex_nopad() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789abcdefghijklmnopqrstuv");
    spec.encoding().unwrap()
}

#[derive(Debug, PartialEq)]
pub struct Hash {
    encoded: String,
}

impl Hash {
    pub fn calculate(bytes: &[u8]) -> Self {
        let mut hasher = Blake2b::new();
        hasher.update(bytes);
        let res = hasher.finalize();

        let encoded = base32hex_nopad().encode(&res[..HASH_SIZE]);
        Hash { encoded }
    }

    pub fn short(&self) -> &str {
        &self.encoded[..TRANS_PROOF_ID_LENGTH]
    }
}

pub fn verify(_db: &[u8], _hash: &Hash, _proof: &[u8]) -> Result<()> {
    // TODO: we probably don't need to validate the CA of the cert, as long as we got SCTs
    // warn!("TODO: verify certificate can be traced to a CA in our trust store");

    warn!("TODO: verify the certificate is valid for <hash>.<domain>");

    warn!("TODO: verify the certificate has at least <n> SCTs from logs we trust");

    warn!("TODO: if configured, send the certificate to additional logs");

    Ok(())
}

pub async fn fetch_and_verify(url: &str, db: &[u8]) -> Result<()> {
    let hash = Hash::calculate(db);

    let url = format!("{}.{}.crt", url, hash.short());
    info!("Trying to download transparency proof from {:?}", url);
    let proof = http::download_to_mem(&url, PROOF_SIZE_LIMIT).await?;
    debug!("Downloaded {} bytes", proof.len());

    info!("Verifying transparency proof");
    verify(&db, &hash, &proof)
}

fn unix_time_millis() -> Result<u64> {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?;
    Ok(dur.as_secs())
}


pub fn parse_cert_pem(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut cur = Cursor::new(bytes);
    let certs = rustls::internal::pemfile::certs(&mut cur).unwrap(); // TODO
    let cert = &certs[0]; // TODO
    Ok(cert.0.clone())
}


pub fn verify_cert_scts(cert: &[u8]) -> Result<usize> {
    let cert = parse_cert_pem(cert)?;

    let now = unix_time_millis()?;

    let scts = parse_scts_from_cert(&cert)?;

    let mut valid_scts = 0;
    for sct in &scts {
        verify_sct(&cert, &sct, now, &ct_logs::LOGS)?;
        valid_scts += 1;
    }
    Ok(valid_scts)
}

fn parse_scts_from_cert(cert: &[u8]) -> Result<Vec<&[u8]>> {
    let extensions = parse_sct_extensions_from_cert(cert)?;

    let mut embedded_scts = Vec::new();
    for ext in extensions {
        for sct in parse_sct_extension(&ext)? {
            embedded_scts.push(sct);
        }
    }

    Ok(embedded_scts)
}

fn parse_sct_extensions_from_cert(cert: &[u8]) -> Result<Vec<&[u8]>> {
    let (rem, x509) = parse_x509_der(cert)?;
    if !rem.is_empty() {
        bail!("Certificate has trailing data");
    }

    if x509.tbs_certificate.version != 2 {
        bail!("Certificate version is expected to be 2");
    }

    let sct_oid = "1.3.6.1.4.1.11129.2.4.2".parse::<Oid>().unwrap();

    let mut extensions = Vec::new();
    for ext in &x509.tbs_certificate.extensions {
        if ext.oid == sct_oid {
            trace!("Found extension matching SCT OID: {:?}", ext);
            let parsed = der_parser::der::parse_der(ext.value)
                .context("Failed to parse SCT extension")?;

            let content = match parsed.1.content {
                BerObjectContent::OctetString(bytes) => bytes,
                content => bail!("Expected octet string, got {:?}", content),
            };

            extensions.push(content);
        }
    }

    Ok(extensions)
}

fn take_u16_bytes(remaining: &[u8]) -> IResult<&[u8], &[u8]> {
    let (remaining, len) = be_u16(remaining)?;
    take(len)(remaining)
}

fn parse_sct_extension(extension: &[u8]) -> Result<Vec<&[u8]>> {
    let mut scts = Vec::new();

    let (remaining, list) = take_u16_bytes(extension)
        .map_err(|err| anyhow!("Failed to take sct_lists: {}", err))?;

    if !remaining.is_empty() {
        todo!()
    }

    let mut bytes = list;
    while !bytes.is_empty() {
        let (remaining, sct) = take_u16_bytes(bytes)
            .map_err(|err| anyhow!("Failed to read sct: {}", err))?;
        scts.push(sct);
        bytes = remaining;
    }

    Ok(scts)
}

pub fn verify_sct(cert: &[u8], sct: &[u8], now: u64, logs: &[&sct::Log]) -> Result<()> {
    match sct::verify_sct(&cert, &sct, now, &logs) {
        Ok(index) => {
            debug!("Valid SCT signed by {} on {}",
            logs[index].operated_by, logs[index].description);
            Ok(())
        }
        Err(err) => bail!("Invalid SCT: {:?}", err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hasher() {
        let hash = Hash::calculate(b"ohai");
        assert_eq!(hash, Hash {
            encoded: "86md6rdv12jaemeaqr10ad47b4u1i2uutj5gblp2rr9peoghugig".to_string(),
        });
        assert_eq!(hash.short(), "86md6rdv12ja");
    }

    #[test]
    fn test_verify_scts() {
        let cert = br#"-----BEGIN CERTIFICATE-----
MIIFVjCCBD6gAwIBAgIQC4dWxaKiBRVzGWo0s0yjYzANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0yMDAzMDUwMDAwMDBaFw0yMTA0MDUx
MjAwMDBaMBIxEDAOBgNVBAMTB2RvY3MucnMwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDfC+I6H+YcA6cHbAGK4kFCCL/WUXasFq1A2zYn4TJhedGYkCCr
BAS/1TWCrbRqmFOWXkp1Y1HdTFbLJjXLJVIBlhv5hqCV56ekr1YqihtG266q10NB
ChAMSalGmAkNkMpFSg/dxwVde2hzZc3KSX3O2Kwfbuuv1ha9OBG1vDtInaGqH6Ht
gj2AGR5RyVq2nUWFQTaFymI1y+iIg3SDh27z0Fr0gLEUzJSax1IEU/8V2hNv3FNP
wL/NGwsft1x9Ax8Zfq3guDEu/QgNfdK8oYXhwlxBz6xlhZIm1HmA9O691Xz/998i
JTgNU832pq0eXS8B8ptIDiYmRObGG+VaI22JAgMBAAGjggJyMIICbjAfBgNVHSME
GDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUUMfyp4W7BNZ+Ra38
aFA27JmUmWQwEgYDVR0RBAswCYIHZG9jcy5yczAOBgNVHQ8BAf8EBAMCBaAwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDsGA1UdHwQ0MDIwMKAuoCyGKmh0
dHA6Ly9jcmwuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLmNybDAgBgNVHSAE
GTAXMAsGCWCGSAGG/WwBAjAIBgZngQwBAgEwdQYIKwYBBQUHAQEEaTBnMC0GCCsG
AQUFBzABhiFodHRwOi8vb2NzcC5zY2ExYi5hbWF6b250cnVzdC5jb20wNgYIKwYB
BQUHMAKGKmh0dHA6Ly9jcnQuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLmNy
dDAMBgNVHRMBAf8EAjAAMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAu9nfvB+K
cbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFwqzCLCAAABAMARzBFAiEAlAB+
rpOl+W58w5uKoHOn7OM8wn2tYNUywg4jYdkLjHICIF1/32j8d6g5H28PRDJBI2MR
6jbwPJyvvsPPW5Tt1VkDAHUA7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvt
xfkAAAFwqzCLWAAABAMARjBEAiAc6h+7OvaC29a8f55LTQ3wNjLn5PrTtsdcWJYF
+q4H9gIgNSicDFUoPEUjmPIamkBMnZnt1YxokKWUeXF0je44mugwDQYJKoZIhvcN
AQELBQADggEBAJo/sW9MGiDr91L+aGSvoNFQXhNS3HWFcSLedfr4FLrPqxO8qZZi
qRdEh/J3GWZgOlNHwNxnUHyyCb84fvPd3wNGoMAXXEFVEwrq2+ufbgwaTZpiIRnA
wqmYlWUk+UnmbA8Sq5vWcI9JHxwW370T7lXmOY0zw3OOSVv9M3zUQseHCIHoYGeY
aq419zefKvINdikSu2IaBJwk8DEZTAurqo9fFTn3Qw0luHcJ4J0kzOsvRMuyZZVf
8LnaglpnkK/PZ5C3/+xyhqC3j0uwmK0iv8gTg/fqiJVT3Q3WcBGSQj/qDa3C4Ms3
hz792e+xQB2AE0UNeHJXrE4LSXAER4h9ABg=
-----END CERTIFICATE-----"#;
        let valid_scts = verify_cert_scts(cert).unwrap();
        assert_eq!(valid_scts, 2);
    }

    #[test]
    fn test_extract_sct_extensions() {
        let cert = br#"-----BEGIN CERTIFICATE-----
MIIFVjCCBD6gAwIBAgIQC4dWxaKiBRVzGWo0s0yjYzANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0yMDAzMDUwMDAwMDBaFw0yMTA0MDUx
MjAwMDBaMBIxEDAOBgNVBAMTB2RvY3MucnMwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDfC+I6H+YcA6cHbAGK4kFCCL/WUXasFq1A2zYn4TJhedGYkCCr
BAS/1TWCrbRqmFOWXkp1Y1HdTFbLJjXLJVIBlhv5hqCV56ekr1YqihtG266q10NB
ChAMSalGmAkNkMpFSg/dxwVde2hzZc3KSX3O2Kwfbuuv1ha9OBG1vDtInaGqH6Ht
gj2AGR5RyVq2nUWFQTaFymI1y+iIg3SDh27z0Fr0gLEUzJSax1IEU/8V2hNv3FNP
wL/NGwsft1x9Ax8Zfq3guDEu/QgNfdK8oYXhwlxBz6xlhZIm1HmA9O691Xz/998i
JTgNU832pq0eXS8B8ptIDiYmRObGG+VaI22JAgMBAAGjggJyMIICbjAfBgNVHSME
GDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUUMfyp4W7BNZ+Ra38
aFA27JmUmWQwEgYDVR0RBAswCYIHZG9jcy5yczAOBgNVHQ8BAf8EBAMCBaAwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDsGA1UdHwQ0MDIwMKAuoCyGKmh0
dHA6Ly9jcmwuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLmNybDAgBgNVHSAE
GTAXMAsGCWCGSAGG/WwBAjAIBgZngQwBAgEwdQYIKwYBBQUHAQEEaTBnMC0GCCsG
AQUFBzABhiFodHRwOi8vb2NzcC5zY2ExYi5hbWF6b250cnVzdC5jb20wNgYIKwYB
BQUHMAKGKmh0dHA6Ly9jcnQuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLmNy
dDAMBgNVHRMBAf8EAjAAMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAu9nfvB+K
cbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFwqzCLCAAABAMARzBFAiEAlAB+
rpOl+W58w5uKoHOn7OM8wn2tYNUywg4jYdkLjHICIF1/32j8d6g5H28PRDJBI2MR
6jbwPJyvvsPPW5Tt1VkDAHUA7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvt
xfkAAAFwqzCLWAAABAMARjBEAiAc6h+7OvaC29a8f55LTQ3wNjLn5PrTtsdcWJYF
+q4H9gIgNSicDFUoPEUjmPIamkBMnZnt1YxokKWUeXF0je44mugwDQYJKoZIhvcN
AQELBQADggEBAJo/sW9MGiDr91L+aGSvoNFQXhNS3HWFcSLedfr4FLrPqxO8qZZi
qRdEh/J3GWZgOlNHwNxnUHyyCb84fvPd3wNGoMAXXEFVEwrq2+ufbgwaTZpiIRnA
wqmYlWUk+UnmbA8Sq5vWcI9JHxwW370T7lXmOY0zw3OOSVv9M3zUQseHCIHoYGeY
aq419zefKvINdikSu2IaBJwk8DEZTAurqo9fFTn3Qw0luHcJ4J0kzOsvRMuyZZVf
8LnaglpnkK/PZ5C3/+xyhqC3j0uwmK0iv8gTg/fqiJVT3Q3WcBGSQj/qDa3C4Ms3
hz792e+xQB2AE0UNeHJXrE4LSXAER4h9ABg=
-----END CERTIFICATE-----"#;
        let cert = parse_cert_pem(cert).unwrap();
        let extensions = parse_sct_extensions_from_cert(&cert).unwrap();
        assert_eq!(extensions, &[
            &[0, 239, 0, 118, 0, 187, 217, 223, 188, 31, 138, 113, 181, 147,
            148, 35, 151, 170, 146, 123, 71, 56, 87, 149, 10, 171, 82, 232, 26,
            144, 150, 100, 54, 142, 30, 209, 133, 0, 0, 1, 112, 171, 48, 139,
            8, 0, 0, 4, 3, 0, 71, 48, 69, 2, 33, 0, 148, 0, 126, 174, 147, 165,
            249, 110, 124, 195, 155, 138, 160, 115, 167, 236, 227, 60, 194,
            125, 173, 96, 213, 50, 194, 14, 35, 97, 217, 11, 140, 114, 2, 32,
            93, 127, 223, 104, 252, 119, 168, 57, 31, 111, 15, 68, 50, 65, 35,
            99, 17, 234, 54, 240, 60, 156, 175, 190, 195, 207, 91, 148, 237,
            213, 89, 3, 0, 117, 0, 238, 192, 149, 238, 141, 114, 100, 15, 146,
            227, 195, 185, 27, 199, 18, 163, 105, 106, 9, 123, 75, 106, 26, 20,
            56, 230, 71, 178, 203, 237, 197, 249, 0, 0, 1, 112, 171, 48, 139,
            88, 0, 0, 4, 3, 0, 70, 48, 68, 2, 32, 28, 234, 31, 187, 58, 246,
            130, 219, 214, 188, 127, 158, 75, 77, 13, 240, 54, 50, 231, 228,
            250, 211, 182, 199, 92, 88, 150, 5, 250, 174, 7, 246, 2, 32, 53,
            40, 156, 12, 85, 40, 60, 69, 35, 152, 242, 26, 154, 64, 76, 157,
            153, 237, 213, 140, 104, 144, 165, 148, 121, 113, 116, 141, 238,
            56, 154, 232][..],
        ]);
    }

    #[test]
    fn test_parse_sct_extension() {
        let scts = parse_sct_extension(&[0, 239, 0, 118, 0, 187,
            217, 223, 188, 31, 138, 113, 181, 147, 148, 35, 151, 170, 146, 123,
            71, 56, 87, 149, 10, 171, 82, 232, 26, 144, 150, 100, 54, 142, 30,
            209, 133, 0, 0, 1, 112, 171, 48, 139, 8, 0, 0, 4, 3, 0, 71, 48, 69,
            2, 33, 0, 148, 0, 126, 174, 147, 165, 249, 110, 124, 195, 155, 138,
            160, 115, 167, 236, 227, 60, 194, 125, 173, 96, 213, 50, 194, 14,
            35, 97, 217, 11, 140, 114, 2, 32, 93, 127, 223, 104, 252, 119, 168,
            57, 31, 111, 15, 68, 50, 65, 35, 99, 17, 234, 54, 240, 60, 156,
            175, 190, 195, 207, 91, 148, 237, 213, 89, 3, 0, 117, 0, 238, 192,
            149, 238, 141, 114, 100, 15, 146, 227, 195, 185, 27, 199, 18, 163,
            105, 106, 9, 123, 75, 106, 26, 20, 56, 230, 71, 178, 203, 237, 197,
            249, 0, 0, 1, 112, 171, 48, 139, 88, 0, 0, 4, 3, 0, 70, 48, 68, 2,
            32, 28, 234, 31, 187, 58, 246, 130, 219, 214, 188, 127, 158, 75,
            77, 13, 240, 54, 50, 231, 228, 250, 211, 182, 199, 92, 88, 150, 5,
            250, 174, 7, 246, 2, 32, 53, 40, 156, 12, 85, 40, 60, 69, 35, 152,
            242, 26, 154, 64, 76, 157, 153, 237, 213, 140, 104, 144, 165, 148,
            121, 113, 116, 141, 238, 56, 154, 232]).unwrap();
        assert_eq!(scts, &[
            &[0, 187, 217, 223, 188, 31, 138, 113, 181, 147, 148, 35, 151, 170,
            146, 123, 71, 56, 87, 149, 10, 171, 82, 232, 26, 144, 150, 100, 54,
            142, 30, 209, 133, 0, 0, 1, 112, 171, 48, 139, 8, 0, 0, 4, 3, 0,
            71, 48, 69, 2, 33, 0, 148, 0, 126, 174, 147, 165, 249, 110, 124,
            195, 155, 138, 160, 115, 167, 236, 227, 60, 194, 125, 173, 96, 213,
            50, 194, 14, 35, 97, 217, 11, 140, 114, 2, 32, 93, 127, 223, 104,
            252, 119, 168, 57, 31, 111, 15, 68, 50, 65, 35, 99, 17, 234, 54,
            240, 60, 156, 175, 190, 195, 207, 91, 148, 237, 213, 89, 3][..],
            &[0, 238, 192, 149, 238, 141, 114, 100, 15, 146, 227, 195, 185, 27,
            199, 18, 163, 105, 106, 9, 123, 75, 106, 26, 20, 56, 230, 71, 178,
            203, 237, 197, 249, 0, 0, 1, 112, 171, 48, 139, 88, 0, 0, 4, 3, 0,
            70, 48, 68, 2, 32, 28, 234, 31, 187, 58, 246, 130, 219, 214, 188,
            127, 158, 75, 77, 13, 240, 54, 50, 231, 228, 250, 211, 182, 199,
            92, 88, 150, 5, 250, 174, 7, 246, 2, 32, 53, 40, 156, 12, 85, 40,
            60, 69, 35, 152, 242, 26, 154, 64, 76, 157, 153, 237, 213, 140,
            104, 144, 165, 148, 121, 113, 116, 141, 238, 56, 154, 232][..],
        ]);
    }

    #[test]
    fn test_extract_scts_from_cert() {
        let cert = br#"-----BEGIN CERTIFICATE-----
MIIFVjCCBD6gAwIBAgIQC4dWxaKiBRVzGWo0s0yjYzANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0yMDAzMDUwMDAwMDBaFw0yMTA0MDUx
MjAwMDBaMBIxEDAOBgNVBAMTB2RvY3MucnMwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDfC+I6H+YcA6cHbAGK4kFCCL/WUXasFq1A2zYn4TJhedGYkCCr
BAS/1TWCrbRqmFOWXkp1Y1HdTFbLJjXLJVIBlhv5hqCV56ekr1YqihtG266q10NB
ChAMSalGmAkNkMpFSg/dxwVde2hzZc3KSX3O2Kwfbuuv1ha9OBG1vDtInaGqH6Ht
gj2AGR5RyVq2nUWFQTaFymI1y+iIg3SDh27z0Fr0gLEUzJSax1IEU/8V2hNv3FNP
wL/NGwsft1x9Ax8Zfq3guDEu/QgNfdK8oYXhwlxBz6xlhZIm1HmA9O691Xz/998i
JTgNU832pq0eXS8B8ptIDiYmRObGG+VaI22JAgMBAAGjggJyMIICbjAfBgNVHSME
GDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUUMfyp4W7BNZ+Ra38
aFA27JmUmWQwEgYDVR0RBAswCYIHZG9jcy5yczAOBgNVHQ8BAf8EBAMCBaAwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDsGA1UdHwQ0MDIwMKAuoCyGKmh0
dHA6Ly9jcmwuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLmNybDAgBgNVHSAE
GTAXMAsGCWCGSAGG/WwBAjAIBgZngQwBAgEwdQYIKwYBBQUHAQEEaTBnMC0GCCsG
AQUFBzABhiFodHRwOi8vb2NzcC5zY2ExYi5hbWF6b250cnVzdC5jb20wNgYIKwYB
BQUHMAKGKmh0dHA6Ly9jcnQuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLmNy
dDAMBgNVHRMBAf8EAjAAMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAu9nfvB+K
cbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFwqzCLCAAABAMARzBFAiEAlAB+
rpOl+W58w5uKoHOn7OM8wn2tYNUywg4jYdkLjHICIF1/32j8d6g5H28PRDJBI2MR
6jbwPJyvvsPPW5Tt1VkDAHUA7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvt
xfkAAAFwqzCLWAAABAMARjBEAiAc6h+7OvaC29a8f55LTQ3wNjLn5PrTtsdcWJYF
+q4H9gIgNSicDFUoPEUjmPIamkBMnZnt1YxokKWUeXF0je44mugwDQYJKoZIhvcN
AQELBQADggEBAJo/sW9MGiDr91L+aGSvoNFQXhNS3HWFcSLedfr4FLrPqxO8qZZi
qRdEh/J3GWZgOlNHwNxnUHyyCb84fvPd3wNGoMAXXEFVEwrq2+ufbgwaTZpiIRnA
wqmYlWUk+UnmbA8Sq5vWcI9JHxwW370T7lXmOY0zw3OOSVv9M3zUQseHCIHoYGeY
aq419zefKvINdikSu2IaBJwk8DEZTAurqo9fFTn3Qw0luHcJ4J0kzOsvRMuyZZVf
8LnaglpnkK/PZ5C3/+xyhqC3j0uwmK0iv8gTg/fqiJVT3Q3WcBGSQj/qDa3C4Ms3
hz792e+xQB2AE0UNeHJXrE4LSXAER4h9ABg=
-----END CERTIFICATE-----"#;
        let cert = parse_cert_pem(cert).unwrap();
        let scts = parse_scts_from_cert(&cert).unwrap();
        assert_eq!(scts, &[
            &[0, 187, 217, 223, 188, 31, 138, 113, 181, 147, 148, 35, 151, 170,
            146, 123, 71, 56, 87, 149, 10, 171, 82, 232, 26, 144, 150, 100, 54,
            142, 30, 209, 133, 0, 0, 1, 112, 171, 48, 139, 8, 0, 0, 4, 3, 0,
            71, 48, 69, 2, 33, 0, 148, 0, 126, 174, 147, 165, 249, 110, 124,
            195, 155, 138, 160, 115, 167, 236, 227, 60, 194, 125, 173, 96, 213,
            50, 194, 14, 35, 97, 217, 11, 140, 114, 2, 32, 93, 127, 223, 104,
            252, 119, 168, 57, 31, 111, 15, 68, 50, 65, 35, 99, 17, 234, 54,
            240, 60, 156, 175, 190, 195, 207, 91, 148, 237, 213, 89, 3][..],
            &[0, 238, 192, 149, 238, 141, 114, 100, 15, 146, 227, 195, 185, 27,
            199, 18, 163, 105, 106, 9, 123, 75, 106, 26, 20, 56, 230, 71, 178,
            203, 237, 197, 249, 0, 0, 1, 112, 171, 48, 139, 88, 0, 0, 4, 3, 0,
            70, 48, 68, 2, 32, 28, 234, 31, 187, 58, 246, 130, 219, 214, 188,
            127, 158, 75, 77, 13, 240, 54, 50, 231, 228, 250, 211, 182, 199,
            92, 88, 150, 5, 250, 174, 7, 246, 2, 32, 53, 40, 156, 12, 85, 40,
            60, 69, 35, 152, 242, 26, 154, 64, 76, 157, 153, 237, 213, 140,
            104, 144, 165, 148, 121, 113, 116, 141, 238, 56, 154, 232][..],
        ]);
    }
}

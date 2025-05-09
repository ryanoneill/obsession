use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::x509::X509;
use openssl::x509::X509Name;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509Builder;
use std::collections::HashMap;
use std::error::Error;

#[allow(dead_code)]
trait ToHashMap<A, B> {
    fn to_hash_map(&self) -> HashMap<A, B>;
}

impl ToHashMap<String, String> for X509Name {
    fn to_hash_map(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();

        for entry in self.entries() {
            let key = entry.object().to_string();
            let value = String::from_utf8_lossy(
                entry.data().as_slice()
            ).to_string();
            result.insert(key, value);
        }

        result
    }
}

fn build_root_name() -> Result<X509Name, Box<dyn Error>> {
    let mut name_builder: X509NameBuilder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", "US")?;
    name_builder.append_entry_by_text("ST", "CA")?;
    name_builder.append_entry_by_text("O", "Rymeon")?;
    name_builder.append_entry_by_text("CN", "Rymeon Root CA")?;
    let name: X509Name = name_builder.build();
    Ok(name)
}

fn build_serial_number(serial: &str) -> Result<Asn1Integer, Box<dyn Error>> {
    let bn_serial = BigNum::from_hex_str(serial)?;
    let asn1_serial = Asn1Integer::from_bn(&bn_serial)?;
    Ok(asn1_serial)
}

fn main() -> Result<(), Box<dyn Error>> {
    let name = build_root_name()?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?; // 10 years
    builder.set_not_before(not_before.as_ref())?;
    builder.set_not_after(not_after.as_ref())?;

    let serial = build_serial_number("1234567890abcdef1234567890abcdef")?;
    builder.set_serial_number(&serial)?;

    let cert: X509 = builder.build();
    println!("{:?}", cert);

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{build_root_name, ToHashMap};

    #[test]
    fn build_root_name_is_ok() {
        let root_name_result = build_root_name();
        assert!(root_name_result.is_ok());
    }

    #[test]
    fn build_root_name_has_4_entries() {
        let root_name = build_root_name().unwrap();
        assert_eq!(root_name.entries().count(), 4);
    }

    #[test]
    fn build_root_name_hashmap() {
        let root_name = build_root_name().unwrap();
        let map = root_name.to_hash_map();
        println!("{:?}", map);
        assert_eq!(map.len(), 4);
        assert!(map.contains_key("countryName"));
        assert_eq!(map["countryName"], "US");
        assert!(map.contains_key("stateOrProvinceName"));
        assert_eq!(map["stateOrProvinceName"], "CA");
        assert!(map.contains_key("organizationName"));
        assert_eq!(map["organizationName"], "Rymeon");
        assert!(map.contains_key("commonName"));
        assert_eq!(map["commonName"], "Rymeon Root CA");
    }

}

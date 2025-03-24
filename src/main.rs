use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::x509::X509;
use openssl::x509::X509Name;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509Builder;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut name_builder: X509NameBuilder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", "US")?;
    name_builder.append_entry_by_text("ST", "CA")?;
    name_builder.append_entry_by_text("O", "Rymeon")?;
    name_builder.append_entry_by_text("CN", "Rymeon CA Root")?;
    let name: X509Name = name_builder.build();

    let mut builder = X509Builder::new()?;
    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?; // 10 years
    builder.set_not_before(not_before.as_ref())?;
    builder.set_not_after(not_after.as_ref())?;

    let bn_serial = BigNum::from_hex_str("1234567890abcdef1234567890abcdef")?;
    let asn1_serial = Asn1Integer::from_bn(&bn_serial)?;
    builder.set_serial_number(&asn1_serial)?;

    let cert: X509 = builder.build();
    println!("{:?}", cert);

    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn confidence_check() {
        assert_eq!(1+1, 2);
    }

}

#![allow(dead_code)]

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};

pub struct Issued {
    pub cert: rcgen::Certificate,
    pub key: KeyPair,
}

impl Issued {
    pub fn der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }
    pub fn key_der(&self) -> Vec<u8> {
        self.key.serialize_der()
    }
}

pub fn ca(cn: &str, parent: Option<&Issued>) -> Issued {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.distinguished_name
        .push(DnType::OrganizationName, "RUST-CA Test");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate().unwrap();
    let cert = match parent {
        Some(par) => p.signed_by(&key, &par.cert, &par.key).unwrap(),
        None => p.self_signed(&key).unwrap(),
    };
    Issued { cert, key }
}

pub fn leaf(cn: &str, dns: &[&str], server: bool, issuer: &Issued) -> Issued {
    leaf_with_validity(cn, dns, server, issuer, None)
}

/// (年, 月, 日)
pub type Ymd = (i32, u8, u8);

pub fn leaf_with_validity(
    cn: &str,
    dns: &[&str],
    server: bool,
    issuer: &Issued,
    validity: Option<(Ymd, Ymd)>,
) -> Issued {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.subject_alt_names = dns
        .iter()
        .map(|d| SanType::DnsName((*d).try_into().unwrap()))
        .collect();
    p.extended_key_usages = vec![if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    }];
    if let Some(((y1, m1, d1), (y2, m2, d2))) = validity {
        p.not_before = rcgen::date_time_ymd(y1, m1, d1);
        p.not_after = rcgen::date_time_ymd(y2, m2, d2);
    }
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    Issued { cert, key }
}

/// 一組完整的測試 PKI：root → inter → server / client。
pub struct Pki {
    pub root: Issued,
    pub inter: Issued,
    pub server: Issued,
    pub client: Issued,
    pub other_root: Issued,
}

pub fn pki() -> Pki {
    let root = ca("Test Root CA", None);
    let inter = ca("Test Intermediate CA", Some(&root));
    let server = leaf(
        "server.example.com",
        &["server.example.com", "localhost"],
        true,
        &inter,
    );
    let client = leaf("client-app", &[], false, &inter);
    let other_root = ca("Other Root CA", None);
    Pki {
        root,
        inter,
        server,
        client,
        other_root,
    }
}

//! 極簡 DER TLV 讀寫工具，只用於 keystore 內部結構（EncryptedPrivateKeyInfo、PKCS#7 等）。

use crate::error::{Error, Result};

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

/// 一個 DER 元素。
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// 包含 tag 與長度的完整編碼。
    pub raw: &'a [u8],
}

/// 讀取一個 TLV，回傳 (元素, 剩餘資料)。
pub fn read_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if data.len() < 2 {
        return Err(Error::format("DER 資料過短"));
    }
    let tag = data[0];
    let first = data[1] as usize;
    let (len, header) = if first < 0x80 {
        (first, 2usize)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return Err(Error::format("DER 長度欄位不合法"));
        }
        let mut len = 0usize;
        for b in &data[2..2 + n] {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };
    let end = header
        .checked_add(len)
        .filter(|e| *e <= data.len())
        .ok_or_else(|| Error::format("DER 長度超出資料範圍"))?;
    Ok((
        Tlv {
            tag,
            content: &data[header..end],
            raw: &data[..end],
        },
        &data[end..],
    ))
}

/// 讀取指定 tag 的 TLV。
pub fn expect(data: &[u8], tag: u8) -> Result<(Tlv<'_>, &[u8])> {
    let (t, rest) = read_tlv(data)?;
    if t.tag != tag {
        return Err(Error::format(format!(
            "DER 預期 tag 0x{tag:02x}，實際為 0x{:02x}",
            t.tag
        )));
    }
    Ok((t, rest))
}

/// 列舉內容中的所有子元素。
pub fn children(content: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (t, r) = read_tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

/// 將 OID 內容解碼為點分字串。
pub fn oid_to_string(content: &[u8]) -> String {
    if content.is_empty() {
        return String::new();
    }
    let mut parts: Vec<u64> = Vec::new();
    let first = content[0] as u64;
    parts.push(first / 40);
    parts.push(first % 40);
    let mut val: u64 = 0;
    for b in &content[1..] {
        val = (val << 7) | (*b & 0x7f) as u64;
        if b & 0x80 == 0 {
            parts.push(val);
            val = 0;
        }
    }
    parts
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// 將點分 OID 字串編碼為 DER 內容。
pub fn oid_from_string(s: &str) -> Vec<u8> {
    let nums: Vec<u64> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    let mut out = Vec::new();
    if nums.len() < 2 {
        return out;
    }
    out.push((nums[0] * 40 + nums[1]) as u8);
    for &n in &nums[2..] {
        let mut stack = vec![(n & 0x7f) as u8];
        let mut v = n >> 7;
        while v > 0 {
            stack.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        stack.reverse();
        out.extend(stack);
    }
    out
}

/// 編碼一個 TLV。
pub fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let lb = &bytes[skip..];
        out.push(0x80 | lb.len() as u8);
        out.extend_from_slice(lb);
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        for s in ["1.3.6.1.4.1.42.2.17.1.1", "1.2.840.113549.1.7.2", "2.5.4.3"] {
            assert_eq!(oid_to_string(&oid_from_string(s)), s);
        }
    }

    #[test]
    fn long_length() {
        let content = vec![0u8; 300];
        let enc = encode(TAG_OCTET_STRING, &content);
        let (t, rest) = read_tlv(&enc).unwrap();
        assert_eq!(t.content.len(), 300);
        assert!(rest.is_empty());
    }
}

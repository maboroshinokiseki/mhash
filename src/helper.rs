use std::{collections::HashMap, path::Path};

use lazy_static::lazy_static;

use libmhash::paranoid_hash::{self, HasherTag};

use crate::args::Args;

pub fn get_hasher_tag_from_extension(path: &Path) -> Option<HasherTag> {
    let extension = path
        .extension()?
        .to_string_lossy()
        .to_ascii_uppercase()
        .replace('-', "_");
    let map = vec![
        ("CRC32C", HasherTag::CRC32C),
        ("CRC32", HasherTag::CRC32),
        ("MD2", HasherTag::MD2),
        ("MD4", HasherTag::MD4),
        ("MD5", HasherTag::MD5),
        ("SHA1", HasherTag::SHA1),
        ("SHA224", HasherTag::SHA2_224),
        ("SHA256", HasherTag::SHA2_256),
        ("SHA384", HasherTag::SHA2_384),
        ("SHA512", HasherTag::SHA2_512),
        ("SHA3_224", HasherTag::SHA3_224),
        ("SHA3_256", HasherTag::SHA3_256),
        ("SHA3_384", HasherTag::SHA3_384),
        ("SHA3_512", HasherTag::SHA3_512),
    ];

    for (key, valua) in map {
        if extension.contains(key) {
            return Some(valua);
        }
    }

    None
}

pub fn get_hasher_tags(args: &Args) -> Vec<HasherTag> {
    let mut tags = vec![];
    if args.crc32 {
        tags.push(HasherTag::CRC32)
    }
    if args.crc32_c {
        tags.push(HasherTag::CRC32C)
    }
    if args.md5 {
        tags.push(HasherTag::MD5);
    }
    if args.sha1 {
        tags.push(HasherTag::SHA1);
    }
    if args.sha224 {
        tags.push(HasherTag::SHA2_224);
    }
    if args.sha256 {
        tags.push(HasherTag::SHA2_256);
    }
    if args.sha384 {
        tags.push(HasherTag::SHA2_384);
    }
    if args.sha512 {
        tags.push(HasherTag::SHA2_512);
    }
    if args.sha3_224 {
        tags.push(HasherTag::SHA3_224);
    }
    if args.sha3_256 {
        tags.push(HasherTag::SHA3_256);
    }
    if args.sha3_384 {
        tags.push(HasherTag::SHA3_384);
    }
    if args.sha3_512 {
        tags.push(HasherTag::SHA3_512);
    }

    tags
}

pub const fn tag_to_str(tag: &HasherTag) -> &'static str {
    match tag {
        HasherTag::CRC32 => "CRC32",
        HasherTag::CRC32C => "CRC32C",
        HasherTag::MD2 => "MD2",
        HasherTag::MD4 => "MD4",
        HasherTag::MD5 => "MD5",
        HasherTag::SHA1 => "SHA1",
        HasherTag::SHA2_224 => "SHA224",
        HasherTag::SHA2_256 => "SHA256",
        HasherTag::SHA2_384 => "SHA384",
        HasherTag::SHA2_512 => "SHA512",
        HasherTag::SHA3_224 => "SHA3-224",
        HasherTag::SHA3_256 => "SHA3-256",
        HasherTag::SHA3_384 => "SHA3-384",
        HasherTag::SHA3_512 => "SHA3-512",
    }
}

pub fn ascii_string_normalize(string: &str, width: usize) -> String {
    assert!(width > 2);
    let bytes = string.as_bytes();
    let mut new_str;
    if bytes.len() <= width {
        new_str = format!("{:>width$}", string);
    } else {
        let left = &bytes[..width / 2 - 1];
        let right = &bytes[bytes.len() - (width - left.len() - 2)..];
        new_str = String::with_capacity(left.len() + right.len() + 2);
        new_str.push_str(std::str::from_utf8(left).unwrap());
        new_str.push_str("..");
        new_str.push_str(std::str::from_utf8(right).unwrap());
    }

    new_str
}

lazy_static! {
    static ref DIGEST_LENGTH_TO_HASHERS: HashMap<usize, Vec<HasherTag>> = {
        let length_hasher_pairs = [
            (paranoid_hash::CRC32::DIGEST_SIZE * 2, HasherTag::CRC32),
            (paranoid_hash::CRC32C::DIGEST_SIZE * 2, HasherTag::CRC32C),
            (paranoid_hash::MD2::DIGEST_SIZE * 2, HasherTag::MD2),
            (paranoid_hash::MD4::DIGEST_SIZE * 2, HasherTag::MD4),
            (paranoid_hash::MD5::DIGEST_SIZE * 2, HasherTag::MD5),
            (paranoid_hash::SHA1::DIGEST_SIZE * 2, HasherTag::SHA1),
            (paranoid_hash::SHA2_224::DIGEST_SIZE * 2, HasherTag::SHA2_224),
            (paranoid_hash::SHA2_256::DIGEST_SIZE * 2, HasherTag::SHA2_256),
            (paranoid_hash::SHA2_384::DIGEST_SIZE * 2, HasherTag::SHA2_384),
            (paranoid_hash::SHA2_512::DIGEST_SIZE * 2, HasherTag::SHA2_512),
            (paranoid_hash::SHA3_224::DIGEST_SIZE * 2, HasherTag::SHA3_224),
            (paranoid_hash::SHA3_256::DIGEST_SIZE * 2, HasherTag::SHA3_256),
            (paranoid_hash::SHA3_384::DIGEST_SIZE * 2, HasherTag::SHA3_384),
            (paranoid_hash::SHA3_512::DIGEST_SIZE * 2, HasherTag::SHA3_512),
        ];

        // simple and stupid validation
        if  length_hasher_pairs.len() != 14 {
            panic!("Not all hashers listed");
        }

        let mut map = HashMap::new();
        for pair in length_hasher_pairs {
            let vec: &mut Vec<_> = map.entry(pair.0).or_default();
            vec.push(pair.1);
        }

        map
    };
}

pub fn get_possible_tags(digest: impl AsRef<str>) -> Option<&'static Vec<HasherTag>> {
    DIGEST_LENGTH_TO_HASHERS.get(&digest.as_ref().len())
}

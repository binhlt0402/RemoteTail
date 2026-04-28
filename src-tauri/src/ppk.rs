use anyhow::{anyhow, Result};
use base64::Engine;
use num_bigint::BigUint;

#[derive(Default)]
struct Argon2Params {
    variant: String,
    memory: u32,
    passes: u32,
    parallelism: u32,
    salt: Vec<u8>,
}

pub fn convert_ppk_to_openssh(ppk_content: &str, passphrase: Option<&str>) -> Result<String> {
    let mut key_type = String::new();
    let mut version = 0u32;
    let mut encryption = String::new();
    let mut comment = String::new();
    let mut pub_lines: Vec<String> = Vec::new();
    let mut priv_lines: Vec<String> = Vec::new();
    let mut argon2 = Argon2Params::default();

    let mut state = "header";
    let mut lines_left = 0usize;

    for line in ppk_content.lines() {
        if state == "pub" {
            pub_lines.push(line.to_string());
            lines_left -= 1;
            if lines_left == 0 { state = "header"; }
            continue;
        }
        if state == "priv" {
            priv_lines.push(line.to_string());
            lines_left -= 1;
            if lines_left == 0 { state = "header"; }
            continue;
        }
        if let Some((k, v)) = line.split_once(": ") {
            match k {
                "PuTTY-User-Key-File-2" => { version = 2; key_type = v.to_string(); }
                "PuTTY-User-Key-File-3" => { version = 3; key_type = v.to_string(); }
                "Encryption"       => { encryption = v.to_string(); }
                "Comment"          => { comment = v.to_string(); }
                "Key-Derivation"   => { argon2.variant = v.to_string(); }
                "Argon2-Memory"    => { argon2.memory = v.trim().parse().unwrap_or(0); }
                "Argon2-Passes"    => { argon2.passes = v.trim().parse().unwrap_or(0); }
                "Argon2-Parallelism" => { argon2.parallelism = v.trim().parse().unwrap_or(0); }
                "Argon2-Salt"      => { argon2.salt = decode_hex(v.trim()); }
                "Public-Lines" => {
                    state = "pub";
                    lines_left = v.trim().parse().unwrap_or(0);
                }
                "Private-Lines" => {
                    state = "priv";
                    lines_left = v.trim().parse().unwrap_or(0);
                }
                _ => {}
            }
        }
    }

    if version == 0 { return Err(anyhow!("Not a PPK file.")); }

    let pub_b64 = pub_lines.join("");
    let pub_bytes = base64::engine::general_purpose::STANDARD.decode(&pub_b64)?;

    let priv_b64 = priv_lines.join("");
    let mut priv_bytes = base64::engine::general_purpose::STANDARD.decode(&priv_b64)?;

    if !encryption.is_empty() && encryption != "none" {
        let pass = passphrase
            .ok_or_else(|| anyhow!("Key is passphrase-protected but no passphrase was provided."))?;
        priv_bytes = if version == 3 {
            decrypt_priv_v3(&priv_bytes, pass, &argon2)?
        } else {
            decrypt_priv_v2(&priv_bytes, pass)?
        };
    }

    let pub_fields = read_fields(&pub_bytes);
    let priv_fields = read_fields(&priv_bytes);

    match key_type.as_str() {
        "ssh-rsa"    => build_rsa_pem(&pub_fields, &priv_fields),
        "ssh-ed25519" => Ok(build_ed25519_openssh(&pub_fields, &priv_fields, &comment)),
        other => Err(anyhow!(
            "PPK key type \"{other}\" is not supported for auto-conversion.\nFix: PuTTYgen → Conversions → Export OpenSSH key → select that file."
        )),
    }
}

// PPK v2: SHA-1 based key derivation, AES-256-CBC, zero IV
fn decrypt_priv_v2(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use sha1::{Digest, Sha1};

    let pass = passphrase.as_bytes();
    let k1 = Sha1::new().chain_update([0u8, 0, 0, 0]).chain_update(pass).finalize();
    let k2 = Sha1::new().chain_update([0u8, 0, 0, 1]).chain_update(pass).finalize();

    let mut key = [0u8; 32];
    key[..20].copy_from_slice(&k1);
    key[20..].copy_from_slice(&k2[..12]);

    let iv = [0u8; 16];

    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
    cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(data)
        .map_err(|e| anyhow!("Decryption error: {:?}", e))
}

// PPK v3: Argon2 key derivation, AES-256-CBC
// Key material layout: [0..32] AES key | [32..48] IV | [48..80] MAC key
fn decrypt_priv_v3(data: &[u8], passphrase: &str, params: &Argon2Params) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use argon2::{Algorithm, Argon2, Params, Version};

    let algorithm = match params.variant.as_str() {
        "Argon2d"  => Algorithm::Argon2d,
        "Argon2i"  => Algorithm::Argon2i,
        _          => Algorithm::Argon2id,
    };

    let argon2_params = Params::new(params.memory, params.passes, params.parallelism, Some(80))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {}", e))?;

    let mut output = vec![0u8; 80];
    Argon2::new(algorithm, Version::V0x13, argon2_params)
        .hash_password_into(passphrase.as_bytes(), &params.salt, &mut output)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {}", e))?;

    let key: &[u8; 32] = output[..32].try_into().unwrap();
    let iv: &[u8; 16]  = output[32..48].try_into().unwrap();

    cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(data)
        .map_err(|e| anyhow!("Decryption error: {:?}", e))
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn read_fields(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= buf.len() {
        let len = u32::from_be_bytes([buf[i], buf[i+1], buf[i+2], buf[i+3]]) as usize;
        i += 4;
        if i + len <= buf.len() {
            out.push(buf[i..i+len].to_vec());
        }
        i += len;
    }
    out
}

fn build_rsa_pem(pub_fields: &[Vec<u8>], priv_fields: &[Vec<u8>]) -> Result<String> {
    if pub_fields.len() < 3 || priv_fields.len() < 4 {
        return Err(anyhow!("Invalid RSA PPK key structure."));
    }
    let n = &pub_fields[2];
    let e = &pub_fields[1];
    let d = &priv_fields[0];
    let p = &priv_fields[1];
    let q = &priv_fields[2];
    let iqmp = &priv_fields[3];

    let d_big = BigUint::from_bytes_be(d);
    let p_big = BigUint::from_bytes_be(p);
    let q_big = BigUint::from_bytes_be(q);
    let dp = (&d_big % (&p_big - 1u32)).to_bytes_be();
    let dq = (&d_big % (&q_big - 1u32)).to_bytes_be();

    let body: Vec<u8> = [
        asn1_int(&[0]),
        asn1_int(n),
        asn1_int(e),
        asn1_int(d),
        asn1_int(p),
        asn1_int(q),
        asn1_int(&dp),
        asn1_int(&dq),
        asn1_int(iqmp),
    ]
    .concat();

    let der = encode_sequence(&body);
    Ok(pem_wrap("RSA PRIVATE KEY", &der))
}

fn build_ed25519_openssh(pub_fields: &[Vec<u8>], priv_fields: &[Vec<u8>], comment: &str) -> String {
    let pubkey = &pub_fields[1];
    let seed = &priv_fields[0];
    let mut privkey = seed.clone();
    privkey.extend_from_slice(pubkey);

    let pub_blob = [ssh_str(b"ssh-ed25519"), ssh_str(pubkey)].concat();

    let check: u32 = rand::random();
    let mut priv_section: Vec<u8> = [
        check.to_be_bytes().to_vec(),
        check.to_be_bytes().to_vec(),
        ssh_str(b"ssh-ed25519"),
        ssh_str(pubkey),
        ssh_str(&privkey),
        ssh_str(comment.as_bytes()),
    ]
    .concat();

    let pad = (8 - priv_section.len() % 8) % 8;
    for i in 1..=pad { priv_section.push(i as u8); }

    let full: Vec<u8> = [
        b"openssh-key-v1\0".to_vec(),
        ssh_str(b"none"),
        ssh_str(b"none"),
        ssh_str(b""),
        1u32.to_be_bytes().to_vec(),
        ssh_str(&pub_blob),
        ssh_str(&priv_section),
    ]
    .concat();

    pem_wrap("OPENSSH PRIVATE KEY", &full)
}

fn ssh_str(data: &[u8]) -> Vec<u8> {
    let mut v = (data.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(data);
    v
}

fn asn1_int(b: &[u8]) -> Vec<u8> {
    let mut b = b;
    while b.len() > 1 && b[0] == 0 && (b[1] & 0x80) == 0 {
        b = &b[1..];
    }
    let mut content = Vec::new();
    if b[0] & 0x80 != 0 { content.push(0); }
    content.extend_from_slice(b);
    let mut out = vec![0x02];
    out.extend_from_slice(&asn1_len(content.len()));
    out.extend_from_slice(&content);
    out
}

fn asn1_len(n: usize) -> Vec<u8> {
    if n < 0x80 { vec![n as u8] }
    else if n < 0x100 { vec![0x81, n as u8] }
    else { vec![0x82, (n >> 8) as u8, (n & 0xff) as u8] }
}

fn encode_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&asn1_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn pem_wrap(label: &str, data: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let lines: String = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n")
}

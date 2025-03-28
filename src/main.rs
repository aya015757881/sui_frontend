use core::str::FromStr;
use shared_crypto::intent::{Intent, IntentMessage};
use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519Signature},
    hash::{Blake2b256, HashFunction},
    traits::{KeyPair, ToFromBytes, Signer},
};
use sui_types::{
    base_types::{ObjectID, SequenceNumber, SuiAddress},
    digests::ObjectDigest,
    transaction::{CallArg, ObjectArg, TransactionData},
    Identifier,
};
// use move_types::{
//     language_storage::{StructTag, TypeTag},
//     account_address::AccountAddress,
// };
use base64::engine::{general_purpose::STANDARD, Engine};
use serde_json::json;
use bech32::FromBase32;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Input {
    pub id: String,
    pub version: u64,
    pub digest: String,
}

impl Input {
    pub fn to_object_ref(
        &self,
    ) -> Result<(ObjectID, SequenceNumber, ObjectDigest)> {
        let object_id = ObjectID::from_str(&self.id)?;
        let sequence = SequenceNumber::from_u64(self.version);
        let digest = ObjectDigest::from_str(&self.digest)?;
        Ok((object_id, sequence, digest))
    }

    pub fn from_object_ref(obj: (ObjectID, SequenceNumber, ObjectDigest)) -> Self {
        let id = obj.0.to_string();
        let version = obj.1.value();
        let digest = obj.2.to_string();
        Self {
            id,
            version,
            digest,
        }
    }
}

fn sk_to_addr(sk: &str) -> SuiAddress {
    let pk = sk_to_pk(sk);
    let mut hasher = Blake2b256::new();
    hasher.update([0u8]);
    hasher.update(pk);
    let hash = hasher.finalize().digest;
    SuiAddress::from_bytes(hash).unwrap()
}

fn sk_to_pk(sk: &str) -> Vec<u8> {
    let (_, data, _) = bech32::decode(sk).unwrap();
    let data = Vec::from_base32(&data).unwrap();
    let sk = Ed25519PrivateKey::from_bytes(&data[1..]).unwrap();
    let keypair = Ed25519KeyPair::from(sk);
    let pk = keypair.public();
    let pk = pk.as_bytes();
    pk.to_vec()
}

fn sk_sign(sk: &str, msg: &[u8]) -> Vec<u8> {
    let (_, data, _) = bech32::decode(sk).unwrap();
    let data = Vec::from_base32(&data).unwrap();
    let sk = Ed25519PrivateKey::from_bytes(&data[1..]).unwrap();
    let keypair = Ed25519KeyPair::from(sk);
    let sig: Ed25519Signature = keypair.sign(msg);
    sig.sig.to_bytes().to_vec()
}

fn shared_object(id: &str, version: u64, mutable: bool) -> CallArg {
    let arg = ObjectArg::SharedObject {
        id: ObjectID::from_str(id).unwrap(),
        initial_shared_version: SequenceNumber::from_u64(version),
        mutable,
    };
    CallArg::Object(arg)
}

fn build_move_call() -> TransactionData {
    let from = "0x31740f7baab504daf514d1cdb99965b921c50309c7410ecc98d9ccba13568ad7";
    let from = SuiAddress::from_str(from).unwrap();

    let package_str = "0x9f9aaa69b60ce1d6863a55c430d4d90b55959f0d7047f08b25fa14695d2a8596";
    let package = ObjectID::from_str(package_str).unwrap();

    let module = "aya_dex";
    let module = Identifier::from_str(module).unwrap();

    let function = "flip";
    let function = Identifier::from_str(function).unwrap();

    let arg = shared_object(
        "0xe4720fee2ecfa5ac9d711ac6dfa154e4bf30acbffb535e496fef3b329646cd9a",
        451,
        true,
    );
    
    let gas = Input {
        id: "0xfe9ad6b2455a2e8e788d33ef6f1185480892b6ee1e0846409cf73515bef5faa0".to_string(),
        version: 455,
        digest: "C819usrk6aT4drHDXEiVQvW5ytvXi1eY9ThoZZmCPLjb".to_string(),
    }.to_object_ref().unwrap();
    
    let gas_budget = 10000000;
    let gas_price = 5000;

    TransactionData::new_move_call(
        from,
        package,
        module,
        function,
        vec![],
        gas,
        vec![arg],
        gas_budget,
        gas_price,
    ).unwrap()
}

fn build_tx() -> Result<String> {
    let sk = "suiprivkey1qz4geqyqpa83waxmnf2vr80qemktms0gzthy5r07j4naaettnvwpkf6swws";
    
    let data = build_move_call();

    let raw_tx = bcs::to_bytes(&data)?;

    let msg = IntentMessage::new(Intent::sui_transaction(), data);
    let msg = bcs::to_bytes(&msg)?;

    let mut hasher = Blake2b256::new();
    hasher.update(&msg);
    
    let hash = hasher.finalize().digest;
    
    let flag = vec![0u8]; // 0 indicates ed25519 scheme
    let sig = sk_sign(sk, hash.as_slice());
    let pk = sk_to_pk(sk);
    
    let sig = [flag, sig, pk].concat();

    let raw_tx = STANDARD.encode(raw_tx);
    let sig = STANDARD.encode(sig);

    Ok(json!({
        "raw_tx": raw_tx,
        "signature": sig,
    }).to_string())
}

fn main() {
    let tx = build_tx().unwrap();
    println!("tx: {}", tx);
}
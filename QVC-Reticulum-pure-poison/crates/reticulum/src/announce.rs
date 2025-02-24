use alloc::boxed::Box;
use alloc::vec;

use ed25519_dalek::Signature;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::encode::{Encode, Write};
use crate::identity::Identity;

#[derive(Debug, Clone)]
pub struct Announce {
    pub identity: Identity,
    pub signature: Signature,
    pub name_hash: [u8; 10],
    pub random_hash: [u8; 10],
    pub app_data: Option<Box<[u8]>>,
    pub destination: [u8; 16],
}

impl Encode for Announce {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.identity.encode(writer)
            + self.name_hash.encode(writer)
            + self.random_hash.encode(writer)
            + self.signature.to_bytes().as_slice().encode(writer)
            + self.app_data.encode(writer)
    }
}

impl Announce {
    pub fn validate(&self) -> bool {
        let mut message = vec![];
        message.extend_from_slice(&self.destination);
        message.extend_from_slice(self.identity.public_key().as_bytes());
        message.extend_from_slice(self.identity.verifying_key().as_bytes());
        message.extend_from_slice(&self.name_hash);
        message.extend_from_slice(&self.random_hash);
        if let Some(data) = self.app_data.as_ref() {
            message.extend_from_slice(&*data);
        }
        self.identity.verify(&message, &self.signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use rand_core::*;

    use crate::destination::Destination;
    use crate::encode::*;
    use crate::identity::Identity;
    use crate::interface::Interface;
    use crate::packet::{Packet, Payload};
    use crate::parse;
    use crate::sign::FixedKeys;

    #[derive(Debug)]
    struct TestInf;
    impl Interface for TestInf {
        const LENGTH: usize = 2;
    }

    #[test]
    fn there_and_back() {
        let (identity, static_key, sign_key) = Identity::generate(OsRng);
        let sign = FixedKeys::new(static_key, sign_key);
        let destination = Destination::single_in(&identity, "testing_app", "fruits");
        let announce = destination.announce([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], None, &sign);
        announce.validate();

        let packet: Packet<'_, TestInf> = Packet::from_announce(announce);

        let mut buf = Vec::new();
        let _ = packet.encode(&mut buf);

        let packet: Packet<TestInf> = parse::packet(&buf).unwrap().1;
        if let Payload::Announce(ann) = packet.data {
            ann.validate();
        }
    }
}

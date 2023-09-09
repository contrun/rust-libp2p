// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Demonstrates how to get a provider and it's multiaddr.

use async_std::task;
use core::pin::Pin;
use core::task::Poll;
use futures::channel::{mpsc, oneshot};
use futures::future::poll_fn;
use futures::prelude::*;
use libp2p::identify;
use libp2p::kad::record::{
    store::{Error as RecordError, MemoryStore},
    Key,
};
use libp2p::kad::{
    AddProviderError, AddProviderOk, BootstrapError, BootstrapOk, GetClosestPeersOk,
    GetProvidersError, GetProvidersOk, Kademlia, KademliaEvent, QueryId, QueryResult,
};
use libp2p::swarm::SwarmBuilder;
use libp2p::{
    development_transport,
    identity::Keypair,
    multiaddr::Multiaddr,
    swarm::{NetworkBehaviour, SwarmEvent},
    PeerId, Swarm, TransportError,
};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

#[derive(Debug)]
enum InitError {
    ListenOn,
    Io(std::io::Error),
    Transport(TransportError<std::io::Error>),
}

impl From<std::io::Error> for InitError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<TransportError<std::io::Error>> for InitError {
    fn from(err: TransportError<std::io::Error>) -> Self {
        Self::Transport(err)
    }
}

impl core::fmt::Display for InitError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for InitError {}

#[derive(Debug)]
enum KadError {
    NoKnownPeers,
    Bootstrap,
    NoProvider,
    Record(RecordError),
    Timeout,
}

impl core::fmt::Display for KadError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for KadError {}

type KadResult = Result<(), KadError>;

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: Kademlia<MemoryStore>,
    identify: identify::Behaviour,
}

impl Behaviour {
    fn new(kad: Kademlia<MemoryStore>, identify: identify::Behaviour) -> Self {
        Self { kad, identify }
    }
}

struct Swarmer {
    name: &'static str,
    peer_id: PeerId,
    addr: Multiaddr,
    queries: HashMap<QueryId, oneshot::Sender<KadResult>>,
    peers: HashMap<PeerId, &'static str>,
    swarm: Swarm<Behaviour>,
}

impl Swarmer {
    async fn new(name: &'static str) -> Result<Self, InitError> {
        let key = Keypair::generate_ed25519();
        let peer_id = PeerId::from(key.public());
        let identify = identify::Behaviour::new(identify::Config::new("test".into(), key.public()));
        let transport = development_transport(key).await?;
        let store = MemoryStore::new(peer_id.clone());
        let kad = Kademlia::new(peer_id.clone(), store);
        let behaviour = Behaviour::new(kad, identify);
        let mut swarm =
            SwarmBuilder::with_tokio_executor(transport, behaviour, peer_id.clone()).build();
        swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())?;
        let addr = loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => break address,
                SwarmEvent::ListenerClosed { .. } => return Err(InitError::ListenOn),
                _ => {}
            }
        };
        Ok(Self {
            name,
            peer_id,
            addr,
            queries: Default::default(),
            peers: Default::default(),
            swarm,
        })
    }

    fn add_peer_name(&mut self, name: &'static str, peer_id: PeerId) {
        self.peers.insert(peer_id, name);
    }

    fn add_peer_address(&mut self, name: &'static str, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
        self.add_peer_name(name, peer_id);
    }

    fn bootstrap(&mut self, ret: oneshot::Sender<KadResult>) {
        match self.swarm.behaviour_mut().kad.bootstrap() {
            Ok(id) => {
                self.queries.insert(id, ret);
            }
            Err(_) => {
                ret.send(Err(KadError::NoKnownPeers)).ok();
            }
        }
    }

    fn start_providing(&mut self, key: Key, ret: oneshot::Sender<KadResult>) {
        match self.swarm.behaviour_mut().kad.start_providing(key) {
            Ok(id) => {
                self.queries.insert(id, ret);
            }
            Err(err) => {
                ret.send(Err(KadError::Record(err))).ok();
            }
        }
    }

    fn get_provider(&mut self, key: Key, ret: oneshot::Sender<KadResult>) {
        let id = self.swarm.behaviour_mut().kad.get_providers(key.clone());
        self.queries.insert(id, ret);
    }

    fn get_name(&self, peer_id: &PeerId) -> &'static str {
        self.peers.get(peer_id).cloned().unwrap_or("")
    }

    fn notify(&mut self, id: QueryId, result: KadResult) {
        if let Some(ret) = self.queries.remove(&id) {
            ret.send(result).ok();
        }
    }
    fn add_swarm_name(&mut self, swarmer: &Swarmer) {
        self.add_peer_name(swarmer.name, swarmer.peer_id.clone());
    }

    fn add_swarm_address(&mut self, swarmer: &Swarmer) {
        self.add_peer_address(swarmer.name, swarmer.peer_id.clone(), swarmer.addr.clone());
    }

    fn spawn(self) -> Ctrl {
        let (tx, mut rx) = mpsc::channel(4);
        let mut swarm = self.swarm;
        task::spawn(poll_fn(move |ctx| {
            loop {
                let event = match Pin::new(&mut rx).poll_next(ctx) {
                    Poll::Ready(Some(event)) => event,
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                };
                match event {
                    CtrlMsg::Bootstrap(ret) => swarm.bootstrap(ret),
                    CtrlMsg::StartProviding(key, ret) => swarm.start_providing(key, ret),
                    CtrlMsg::GetProvider(key, ret) => swarm.get_provider(key, ret),
                }
            }
            loop {
                match Pin::new(&mut swarm).poll_next(ctx) {
                    Poll::Ready(Some(event)) => match event {
                        SwarmEvent::Behaviour(BehaviourEvent::Identify(
                            identify::Event::Received { peer_id, info, .. },
                        )) => {
                            for addr in info.listen_addrs {
                                self.kad.add_address(&peer_id, addr);
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Kad(
                            KademliaEvent::OutboundQueryProgressed {
                                id, result, stats, ..
                            },
                        )) => {
                            let stats = format!(
                                "{}/{}/{}",
                                stats.num_requests(),
                                stats.num_successes(),
                                stats.num_failures()
                            );
                            match result {
                                QueryResult::Bootstrap(Ok(BootstrapOk {
                                    num_remaining,
                                    peer,
                                })) => {
                                    println!(
                                        "{}: bootstrap {} {}",
                                        self.name,
                                        self.get_name(&peer),
                                        &stats
                                    );
                                    if num_remaining == 0 {
                                        self.notify(id, Ok(()));
                                    }
                                }
                                QueryResult::Bootstrap(Err(BootstrapError::Timeout {
                                    num_remaining,
                                    peer,
                                })) => {
                                    println!(
                                        "{}: bootstrap timeout {} {:?} {}",
                                        self.name,
                                        self.get_name(&peer),
                                        num_remaining,
                                        &stats
                                    );
                                    match num_remaining {
                                        Some(0) => self.notify(id, Ok(())),
                                        None => self.notify(id, Err(KadError::Bootstrap)),
                                        _ => {}
                                    }
                                }
                                QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders {
                                    key: _,
                                    providers,
                                    closest_peers: _,
                                })) => {
                                    println!("{}: get providers {}", self.name, &stats);
                                    if providers.is_empty() {
                                        self.notify(id, Err(KadError::NoProvider));
                                    } else {
                                        self.notify(id, Ok(()));
                                    }
                                }
                                QueryResult::GetProviders(Err(GetProvidersError::Timeout {
                                    ..
                                })) => {
                                    println!("{}: get providers timeout {}", self.name, &stats);
                                    self.notify(id, Err(KadError::Timeout));
                                }
                                QueryResult::StartProviding(Ok(AddProviderOk { .. })) => {
                                    println!("{}: start providing {}", self.name, &stats);
                                    self.notify(id, Ok(()));
                                }
                                QueryResult::StartProviding(Err(AddProviderError::Timeout {
                                    ..
                                })) => {
                                    println!("{}: start providing timeout {}", self.name, &stats);
                                    self.notify(id, Err(KadError::Timeout));
                                }
                                QueryResult::GetClosestPeers(Ok(GetClosestPeersOk { .. })) => {
                                    println!("{}: get closest peers {}", self.name, &stats);
                                }
                                q => println!("{}: {} {:#?}", self.name, &stats, q),
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Kad(
                            KademliaEvent::RoutingUpdated { peer, .. },
                        )) => {
                            println!("{}: routing updated {}", self.name, self.get_name(&peer));
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Kad(
                            KademliaEvent::UnroutablePeer { peer },
                        )) => {
                            println!("{}: unroutable peer {}", self.name, self.get_name(&peer));
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Kad(KademliaEvent::Discovered {
                            peer_id,
                            ..
                        })) => {
                            println!("{}: discovered {}", self.name, self.get_name(&peer_id));
                        }
                    },
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            Poll::Pending
        }));
        Ctrl { tx }
    }
}

#[derive(Debug)]
enum CtrlMsg {
    Bootstrap(oneshot::Sender<KadResult>),
    StartProviding(Key, oneshot::Sender<KadResult>),
    GetProvider(Key, oneshot::Sender<KadResult>),
}

struct Ctrl {
    tx: mpsc::Sender<CtrlMsg>,
}

impl Ctrl {
    async fn bootstrap(&mut self) -> KadResult {
        let (tx, rx) = oneshot::channel();
        self.tx.send(CtrlMsg::Bootstrap(tx)).await.unwrap();
        rx.await.unwrap()
    }

    async fn start_providing(&mut self, key: Key) -> KadResult {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(CtrlMsg::StartProviding(key, tx))
            .await
            .unwrap();
        rx.await.unwrap()
    }

    async fn get_provider(&mut self, key: Key) -> KadResult {
        let (tx, rx) = oneshot::channel();
        self.tx.send(CtrlMsg::GetProvider(key, tx)).await.unwrap();
        rx.await.unwrap()
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let key = Key::new(&[1u8]);

    let mut boot = Swarmer::new("boot").await?;
    let mut tx = Swarmer::new("tx").await?;
    let mut rx = Swarmer::new("rx").await?;

    boot.add_name(&tx);
    boot.add_name(&rx);

    tx.add_address(&boot);
    tx.add_name(&rx);

    rx.add_address(&boot);
    rx.add_name(&tx);

    let _boot = boot.spawn();
    // make sure boot node started before peers
    task::sleep(Duration::from_millis(100)).await;
    let mut tx = tx.spawn();
    let mut rx = rx.spawn();

    tx.bootstrap().await?;
    rx.bootstrap().await?;
    tx.start_providing(key.clone()).await?;
    // make sure the record had time to propagate
    task::sleep(Duration::from_millis(500)).await;
    rx.get_provider(key).await?;
    Ok(())
}

fn main() {
    task::block_on(run()).unwrap();
}

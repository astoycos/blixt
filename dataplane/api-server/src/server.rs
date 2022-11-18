use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Error;
use aya::maps::{HashMap, MapRefMut};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::backends::backends_server::Backends;
use crate::backends::{Confirmation, Targets, Vip};
use common::{Backend, BackendKey};

pub struct BackendService {
    bpf_map: Arc<Mutex<HashMap<MapRefMut, BackendKey, Backend>>>,
}

impl BackendService {
    pub fn new(bpf_map: HashMap<MapRefMut, BackendKey, Backend>) -> BackendService {
        BackendService {
            bpf_map: Arc::new(Mutex::new(bpf_map)),
        }
    }

    async fn insert(&self, key: BackendKey, bk: Backend) -> Result<(), Error> {
        let mut bpf_map = self.bpf_map.lock().await;
        bpf_map.insert(key, bk, 0)?;
        Ok(())
    }

    async fn remove(&self, key: BackendKey) -> Result<(), Error> {
        let mut bpf_map = self.bpf_map.lock().await;
        bpf_map.remove(&key)?;
        Ok(())
    }
}

#[tonic::async_trait]
impl Backends for BackendService {
    async fn update(&self, request: Request<Targets>) -> Result<Response<Confirmation>, Status> {
        let targets = request.into_inner();

        let vip = match targets.vip {
            Some(vip) => vip,
            None => return Err(Status::invalid_argument("missing vip ip and port")),
        };

        let target = match targets.target {
            Some(target) => target,
            None => return Err(Status::invalid_argument("missing targets for vip")),
        };

        let key = BackendKey {
            ip: vip.ip,
            port: vip.port,
        };

        let bk = Backend {
            daddr: target.daddr,
            dport: target.dport,
            ifindex: target.ifindex as u16,
        };

        match self.insert(key, bk).await {
            Ok(_) => Ok(Response::new(Confirmation {
                confirmation: format!(
                    "success, vip {}:{} was updated",
                    Ipv4Addr::from(vip.ip),
                    vip.port
                ),
            })),
            Err(err) => Err(Status::internal(format!("failure: {}", err))),
        }
    }

    async fn delete(&self, request: Request<Vip>) -> Result<Response<Confirmation>, Status> {
        let vip = request.into_inner();

        let key = BackendKey {
            ip: vip.ip,
            port: vip.port,
        };

        let addr_ddn = Ipv4Addr::from(vip.ip);

        match self.remove(key).await {
            Ok(()) => Ok(Response::new(Confirmation {
                confirmation: format!("success, vip {}:{} was deleted", addr_ddn, vip.port),
            })),
            Err(err) if err.to_string().contains("syscall failed with code -1") => {
                Ok(Response::new(Confirmation {
                    confirmation: format!("success, vip {}:{} did not exist", addr_ddn, vip.port),
                }))
            }
            Err(err) => Err(Status::internal(format!("failure: {}", err))),
        }
    }
}

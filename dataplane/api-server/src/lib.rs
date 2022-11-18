pub mod backends;
pub mod server;

use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::Error;
use aya::maps::{HashMap, MapRefMut};
use tonic::transport::Server;

use backends::backends_server::BackendsServer;
use common::{Backend, BackendKey};

pub async fn start(
    addr: Ipv4Addr,
    port: u16,
    bpf_map: HashMap<MapRefMut, BackendKey, Backend>,
) -> Result<(), Error> {
    let server = server::BackendService::new(bpf_map);
    Server::builder()
        .add_service(BackendsServer::new(server))
        .serve(SocketAddrV4::new(addr, port).into())
        .await?;
    Ok(())
}

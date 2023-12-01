/*
Copyright 2023 The Kubernetes Authors.

SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
*/

use core::mem;

use aya_bpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE},
    helpers::bpf_csum_diff,
    programs::TcContext,
};
use aya_log_ebpf::info;
use common::{ClientKey, TCPBackend, TCPState};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

use crate::{
    utils::{csum_fold_helper, handle_tcp_conn_close, ptr_at},
    TCP_CONNECTIONS,
};

pub fn handle_tcp_egress(ctx: TcContext) -> Result<i32, i64> {
    // gather the TCP header
    let ip_hdr: *mut Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

    let tcp_header_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let tcp_hdr: *mut TcpHdr = unsafe { ptr_at(&ctx, tcp_header_offset)? };

    // capture some IP and port information
    let client_addr = unsafe { (*ip_hdr).dst_addr };
    let dest_port = unsafe { (*tcp_hdr).dest };
    // The source identifier
    let client_key = ClientKey {
        ip: u32::from_be(client_addr),
        port: u16::from_be(dest_port) as u32,
    };
    let tcp_backend = unsafe { TCP_CONNECTIONS.get(&client_key) }.ok_or(TC_ACT_PIPE)?;

    info!(
        &ctx,
        "Received TCP packet destined for tracked IP {:i}:{} setting source IP to VIP {:i}:{}",
        u32::from_be(client_addr),
        u16::from_be(dest_port),
        tcp_backend.backend_key.ip,
        tcp_backend.backend_key.port,
    );

    // SNAT the ip address
    unsafe {
        (*ip_hdr).src_addr = tcp_backend.backend_key.ip;
    };

    if (ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN) > ctx.data_end() {
        info!(&ctx, "Iphdr is out of bounds");
        return Ok(TC_ACT_OK);
    }

    unsafe { (*ip_hdr).check = 0 };
    let full_cksum = unsafe {
        bpf_csum_diff(
            mem::MaybeUninit::zeroed().assume_init(),
            0,
            ip_hdr as *mut u32,
            Ipv4Hdr::LEN as u32,
            0,
        )
    } as u64;
    unsafe { (*ip_hdr).check = csum_fold_helper(full_cksum) };
    unsafe { (*tcp_hdr).check = 0 };

    // TODO: connection tracking cleanup https://github.com/kubernetes-sigs/blixt/issues/85
    // SNAT the port
    unsafe { (*tcp_hdr).source = tcp_backend.backend_key.port as u16 };

    let tcp_hdr_ref = unsafe { tcp_hdr.as_ref().ok_or(TC_ACT_OK)? };

    // If the packet has the RST flag set, it means the connection is being terminated, so remove it
    // from our map.
    if tcp_hdr_ref.rst() == 1 {
        unsafe {
            TCP_CONNECTIONS.remove(&client_key)?;
        }
    }

    let mut tcp_state = tcp_backend.state;
    let moved = handle_tcp_conn_close(tcp_hdr_ref, &mut tcp_state);
    // If the connection has moved to the Closed state, stop tracking it.
    if let TCPState::Closed = tcp_state {
        unsafe {
            TCP_CONNECTIONS.remove(&client_key)?;
        }
    // If the connection has not reached the Closed state yet, but it did advance to a new state,
    // then record the new state.
    } else if moved {
        let bk = *tcp_backend;
        let new_tcp_backend = TCPBackend {
            backend: bk.backend,
            backend_key: bk.backend_key,
            state: tcp_state,
        };
        unsafe {
            TCP_CONNECTIONS.insert(&client_key, &new_tcp_backend, 0_u64)?;
        }
    }

    Ok(TC_ACT_PIPE)
}

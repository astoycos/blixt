/*
Copyright 2023 The Kubernetes Authors.

SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
*/

use core::mem;

use aya_bpf::{
    bindings::TC_ACT_OK,
    helpers::{bpf_csum_diff, bpf_redirect_neigh},
    programs::TcContext,
};
use aya_log_ebpf::{debug, info};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

use crate::{
    utils::{csum_fold_helper, handle_tcp_conn_close, ptr_at},
    BACKENDS, GATEWAY_INDEXES, TCP_CONNECTIONS,
};
use common::{Backend, BackendKey, ClientKey, TCPBackend, TCPState, BACKENDS_ARRAY_CAPACITY};

pub fn handle_tcp_ingress(ctx: TcContext) -> Result<i32, i64> {
    let ip_hdr: *mut Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

    let tcp_header_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let tcp_hdr: *mut TcpHdr = unsafe { ptr_at(&ctx, tcp_header_offset) }?;

    let original_daddr = unsafe { (*ip_hdr).dst_addr };

    // The source identifier
    let client_key = ClientKey {
        ip: u32::from_be(unsafe { (*ip_hdr).src_addr }),
        port: (u16::from_be(unsafe { (*tcp_hdr).source })) as u32,
    };
    // The backend that is responsible for handling this TCP connection.
    let mut backend: Backend;
    // Flag to check whether this is a new connection.
    let mut new_conn = false;
    // The state of this TCP connection.
    let mut tcp_state = TCPState::default();

    // Try to find the backend previously used for this connection. If not found, it means that
    // this is a new connection, so assign it the next backend in line.
    if let Some(val) = unsafe { TCP_CONNECTIONS.get(&client_key) } {
        backend = val.backend;
        tcp_state = val.state;
    } else {
        new_conn = true;

        let backend_key = BackendKey {
            ip: u32::from_be(original_daddr),
            port: (u16::from_be(unsafe { (*tcp_hdr).dest })) as u32,
        };
        let backend_list = unsafe { BACKENDS.get(&backend_key) }.ok_or(TC_ACT_OK)?;
        let backend_index = unsafe { GATEWAY_INDEXES.get(&backend_key) }.ok_or(TC_ACT_OK)?;

        debug!(&ctx, "Destination backend index: {}", *backend_index);
        debug!(&ctx, "Backends length: {}", backend_list.backends_len);

        // this check asserts that we don't use a "zero-value" Backend
        if backend_list.backends_len <= *backend_index {
            return Ok(TC_ACT_OK);
        }
        // this check is to make the verifier happy
        if *backend_index as usize >= BACKENDS_ARRAY_CAPACITY {
            return Ok(TC_ACT_OK);
        }

        backend = backend_list.backends[0];
        if let Some(val) = backend_list.backends.get(*backend_index as usize) {
            backend = *val;
        }

        // move the index to the next backend in our list
        let mut next = *backend_index + 1;
        if next >= backend_list.backends_len {
            next = 0;
        }
        unsafe {
            GATEWAY_INDEXES.insert(&backend_key, &next, 0_u64)?;
        }
    }

    info!(
        &ctx,
        "Received a TCP packet destined for svc ip: {:i} at Port: {} ",
        u32::from_be(original_daddr),
        u16::from_be(unsafe { (*tcp_hdr).dest })
    );

    // DNAT the ip address
    unsafe {
        (*ip_hdr).dst_addr = backend.daddr.to_be();
    }

    if (ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN) > ctx.data_end() {
        info!(&ctx, "Iphdr is out of bounds");
        return Ok(TC_ACT_OK);
    }

    // Calculate l3 cksum
    // TODO(astoycos) use l3_cksum_replace instead
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
    // FIXME
    unsafe { (*tcp_hdr).check = 0 };

    let original_dport = unsafe { (*tcp_hdr).dest };
    // DNAT the port
    unsafe { (*tcp_hdr).dest = (backend.dport as u16).to_be() };

    let action = unsafe {
        bpf_redirect_neigh(
            backend.ifindex as u32,
            mem::MaybeUninit::zeroed().assume_init(),
            0,
            0,
        )
    };

    let tcp_hdr_ref = unsafe { tcp_hdr.as_ref().ok_or(TC_ACT_OK)? };

    // If the connection is new, then record it in our map for future tracking.
    if new_conn {
        let tcp_backend = TCPBackend {
            backend,
            backend_key: BackendKey {
                ip: original_daddr,
                port: original_dport as u32,
            },
            state: tcp_state,
        };
        unsafe {
            TCP_CONNECTIONS.insert(&client_key, &tcp_backend, 0_u64)?;
        }

        // since this is a new connection, there is nothing else to do, so exit early
        info!(&ctx, "redirect action: {}", action);
        return Ok(action as i32);
    }

    // If the packet has the RST flag set, it means the connection is being terminated, so remove it
    // from our map.
    if tcp_hdr_ref.rst() == 1 {
        unsafe {
            TCP_CONNECTIONS.remove(&client_key)?;
        }
    }

    let moved = handle_tcp_conn_close(tcp_hdr_ref, &mut tcp_state);
    // If the connection has moved to the Closed state, stop tracking it.
    if let TCPState::Closed = tcp_state {
        unsafe {
            TCP_CONNECTIONS.remove(&client_key)?;
        }
    // If the connection has not reached the Closed state yet, but it did advance to a new state,
    // then record the new state.
    } else if moved {
        let tcp_backend = TCPBackend {
            backend,
            backend_key: BackendKey {
                ip: original_daddr,
                port: original_dport as u32,
            },
            state: tcp_state,
        };
        unsafe {
            TCP_CONNECTIONS.insert(&client_key, &tcp_backend, 0_u64)?;
        }
    }

    info!(&ctx, "redirect action: {}", action);
    Ok(action as i32)
}

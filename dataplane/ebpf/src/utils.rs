/*
Copyright 2023 The Kubernetes Authors.

SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
*/

use aya_bpf::{bindings::TC_ACT_OK, programs::TcContext};
use core::mem;
use network_types::tcp::TcpHdr;

use common::TCPState;

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

// Gives us raw pointers to a specific offset in the packet
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, i64> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(TC_ACT_OK.into());
    }
    Ok((start + offset) as *mut T)
}

// Converts a checksum into u16
#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return !(csum as u16);
}

// Handles the termination of connection.
// Ref: https://en.wikipedia.org/wiki/File:Tcp_state_diagram.png and
// http://www.tcpipguide.com/free/t_TCPConnectionTermination-2.htm
#[inline(always)]
pub fn handle_tcp_conn_close(hdr: &TcpHdr, state: &mut TCPState) -> bool {
    let fin = hdr.fin() == 1;
    let ack = hdr.ack() == 1;
    match state {
        TCPState::Established => {
            // At the Established state, a FIN packet moves the state to FinWait1.
            if fin {
                *state = TCPState::FinWait1;
                return true;
            }
        }
        TCPState::FinWait1 => {
            // At the FinWait1 state, a packet with both the FIN and ACK bits set
            // moves the state to TimeWait.
            if fin && ack {
                *state = TCPState::TimeWait;
                return true;
            }
            // At the FinWait1 state, a FIN packet moves the state to Closing.
            if fin {
                *state = TCPState::Closing;
                return true;
            }
            // At the FinWait1 state, an ACK packet moves the state to FinWait2.
            if ack {
                *state = TCPState::FinWait2;
                return true;
            }
        }
        TCPState::FinWait2 => {
            // At the FinWait2 state, an ACK packet moves the state to TimeWait.
            if ack {
                *state = TCPState::TimeWait;
                return true;
            }
        }
        TCPState::Closing => {
            // At the Closing state, an ACK packet moves the state to TimeWait.
            if ack {
                *state = TCPState::TimeWait;
                return true;
            }
        }
        TCPState::TimeWait => {
            if ack {
                *state = TCPState::Closed;
                return true;
            }
        }
        TCPState::Closed => {}
    }
    return false;
}

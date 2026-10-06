// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// `MuxerRxQ` implements a helper object that `VsockMuxer` can use for queuing RX (host -> guest)
/// packets (or rather instructions on how to build said packets).
///
/// Under ideal operation, every connection, that has pending RX data, will be present in the muxer
/// RX queue. However, since the RX queue is smaller than the connection pool, it may, under some
/// conditions, become full, meaning that it can no longer account for all the connections that can
/// yield RX data.  When that happens, we say that it is no longer "synchronized" (i.e. with the
/// connection pool).  A desynchronized RX queue still holds valid data, and the muxer will
/// continue to pop packets from it. However, when a desynchronized queue is drained, additional
/// data may still be available, so the muxer will have to perform a more costly walk of the entire
/// connection pool to find it.  This walk is performed here, as part of building an RX queue from
/// the connection pool. When an out-of-sync is drained, the muxer will discard it, and attempt to
/// rebuild a synced one.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use vm_memory::GuestMemoryMmap;

use super::super::Queue as VirtQueue;

use super::defs;
use super::defs::uapi;
use super::muxer::MuxerRx;
use super::packet::VsockPacket;
#[cfg(unix)]
use super::packet::{TsiAcceptRsp, TsiConnectRsp, TsiListenRsp};

/// The muxer RX queue.
pub struct MuxerRxQ {
    /// The RX queue data.
    q: VecDeque<MuxerRx>,
    /// The RX queue sync status.
    synced: bool,
}

impl MuxerRxQ {
    const SIZE: usize = defs::MUXER_RXQ_SIZE;

    /// Trivial RX queue constructor.
    pub fn new() -> Self {
        Self {
            q: VecDeque::with_capacity(Self::SIZE),
            synced: true,
        }
    }

    /// Push a new RX item to the queue.
    ///
    /// A push will fail when:
    /// - trying to push a connection key onto an out-of-sync, or full queue; or
    /// - trying to push an RST onto a queue already full of RSTs.
    ///
    /// RSTs take precedence over connections, because connections can always be queried for
    /// pending RX data later. Aside from this queue, there is no other storage for RSTs, so
    /// failing to push one means that we have to drop the packet.
    ///
    /// Returns:
    /// - `true` if the new item has been successfully queued; or
    /// - `false` if there was no room left in the queue.
    pub fn push(&mut self, rx: MuxerRx) -> bool {
        // Pushing to a non-full, synchronized queue will always succeed.
        if self.is_synced() && !self.is_full() {
            self.q.push_back(rx);
            return true;
        }

        false
    }

    /// Pop an RX item from the front of the queue.
    pub fn pop(&mut self) -> Option<MuxerRx> {
        self.q.pop_front()
    }

    /// Check if the RX queue is synchronized with the connection pool.
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Get the total number of items in the queue.
    pub fn len(&self) -> usize {
        self.q.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.len() == Self::SIZE
    }

    /// Drops connection-local responses after the owning muxer has stopped.
    pub(crate) fn clear(&mut self) {
        self.q.clear();
        self.synced = true;
    }
}

/// Deliver or queue a control packet. A false result leaves retry ownership
/// with the caller; the bounded queue must never silently acknowledge delivery.
pub fn push_packet(
    cid: u64,
    rx: MuxerRx,
    rxq_mutex: &Arc<Mutex<MuxerRxQ>>,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &GuestMemoryMmap,
) -> bool {
    let mut queue = queue_mutex.lock().unwrap();
    let mut rxq = rxq_mutex.lock().unwrap();
    if !rxq.is_empty() {
        return rxq.push(rx);
    }

    while let Some(head) = queue.pop(mem) {
        match VsockPacket::from_rx_virtq_head(&head) {
            Ok(mut pkt) => {
                if !rx_to_pkt(cid, rx, &mut pkt) {
                    queue.undo_pop();
                    return false;
                }
                return queue
                    .add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len())
                    .map_err(|err| error!("failed to add used elements to the queue: {err:?}"))
                    .is_ok();
            }
            Err(err) => {
                warn!("invalid vsock RX descriptor: {err:?}");
                if let Err(err) = queue.add_used(mem, head.index, 0) {
                    error!("failed to return invalid RX descriptor: {err:?}");
                    return false;
                }
            }
        }
    }
    rxq.push(rx)
}

pub fn rx_to_pkt(cid: u64, rx: MuxerRx, pkt: &mut VsockPacket) -> bool {
    pkt.hdr_mut().fill(0);
    match rx {
        MuxerRx::Reset {
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_len(0)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);
        }
        #[cfg(unix)]
        MuxerRx::ConnResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_connect_rsp(TsiConnectRsp { result });
            pkt.set_len(pkt.buf().unwrap().len() as u32);
        }
        MuxerRx::OpRequest {
            buf_alloc,
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_REQUEST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(buf_alloc);

            pkt.set_len(0);
        }
        MuxerRx::OpResponse {
            buf_alloc,
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RESPONSE)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(buf_alloc);

            pkt.set_len(0);
        }
        #[cfg(unix)]
        MuxerRx::GetnameResponse {
            local_port,
            peer_port,
            data,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_getname_rsp(data);
            pkt.set_len(pkt.buf().unwrap().len() as u32);
        }
        MuxerRx::CreditRequest {
            buf_alloc,
            local_port,
            peer_port,
            fwd_cnt,
        } => {
            pkt.set_op(uapi::VSOCK_OP_CREDIT_REQUEST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(buf_alloc)
                .set_fwd_cnt(fwd_cnt);
        }
        MuxerRx::CreditUpdate {
            buf_alloc,
            local_port,
            peer_port,
            fwd_cnt,
        } => {
            pkt.set_op(uapi::VSOCK_OP_CREDIT_UPDATE)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(buf_alloc)
                .set_fwd_cnt(fwd_cnt);
        }
        #[cfg(unix)]
        MuxerRx::ListenResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_listen_rsp(TsiListenRsp { result });
            pkt.set_len(pkt.buf().unwrap().len() as u32);
        }
        #[cfg(unix)]
        MuxerRx::AcceptResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_accept_rsp(TsiAcceptRsp { result });
            pkt.set_len(pkt.buf().unwrap().len() as u32);
        }
        #[cfg(unix)]
        MuxerRx::Datagram {
            local_port,
            peer_port,
            data,
        } => {
            let Some(capacity) = pkt.buf().map(|buf| buf.len()) else {
                return false;
            };
            if data.len() > capacity {
                // Virtio-vsock datagrams are atomic. A short guest buffer must
                // drop the message rather than manufacture a truncated one.
                return false;
            }

            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);

            let buf = pkt.buf_mut().expect("datagram buffer was validated above");
            buf[..data.len()].copy_from_slice(&data);
            pkt.set_len(data.len() as u32);
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::virtio::{Descriptor, DescriptorChain};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    #[test]
    fn invalid_rx_descriptor_is_returned_before_delivering_control() {
        use crate::virtio::queue::tests::VirtQueue as TestQueue;

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let guest_queue = TestQueue::new(GuestAddress(0), &mem, 2);
        for index in 0..2 {
            guest_queue.dtable[index]
                .addr
                .set(0x2000 + index as u64 * 128);
            guest_queue.dtable[index].len.set(128);
            guest_queue.dtable[index]
                .flags
                .set(if index == 0 { 0 } else { 2 });
            guest_queue.avail.ring[index].set(index as u16);
        }
        guest_queue.avail.idx.set(2);
        let queue = Arc::new(Mutex::new(guest_queue.create_queue()));
        let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));

        super::super::muxer::push_packet(
            3,
            MuxerRx::CreditUpdate {
                buf_alloc: 65536,
                local_port: 1,
                peer_port: 2,
                fwd_cnt: 32768,
            },
            &rxq,
            &queue,
            &mem,
        );

        assert_eq!(guest_queue.used.idx.get(), 2);
        assert_eq!(guest_queue.used.ring[0].get().id, 0);
        assert_eq!(guest_queue.used.ring[0].get().len, 0);
        assert_eq!(guest_queue.used.ring[1].get().id, 1);
        assert_eq!(guest_queue.used.ring[1].get().len, 44);
    }

    #[test]
    fn credit_packets_clear_stale_guest_header_fields() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        mem.write_obj(
            Descriptor {
                addr: 0x2000,
                len: 128,
                flags: 2,
                next: 0,
            },
            GuestAddress(0x1000),
        )
        .unwrap();
        for rx in [
            MuxerRx::CreditRequest {
                buf_alloc: 65536,
                local_port: 1,
                peer_port: 2,
                fwd_cnt: 32768,
            },
            MuxerRx::CreditUpdate {
                buf_alloc: 65536,
                local_port: 1,
                peer_port: 2,
                fwd_cnt: 32768,
            },
        ] {
            mem.write_slice(&[0xff; 128], GuestAddress(0x2000)).unwrap();
            let head = DescriptorChain::checked_new(&mem, GuestAddress(0x1000), 1, 0).unwrap();
            let mut pkt = VsockPacket::from_rx_virtq_head(&head).unwrap();
            assert!(rx_to_pkt(3, rx, &mut pkt));
            assert_eq!(pkt.len(), 0);
            assert_eq!(pkt.flags(), 0);
            assert_eq!(pkt.fwd_cnt(), 32768);
        }
    }
}

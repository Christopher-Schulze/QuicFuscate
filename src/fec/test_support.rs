use super::FecPacket;
use crate::optimize::MemoryPool;
use aligned_box::AlignedBox;
use std::collections::VecDeque;
use std::env;
use std::ffi::OsString;
use std::sync::Arc;

pub struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    pub fn set(key: &'static str, val: &str) -> Self {
        let prev = env::var_os(key);
        env::set_var(key, val);
        Self { key, prev }
    }
    pub fn unset(key: &'static str) -> Self {
        let prev = env::var_os(key);
        env::remove_var(key);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => env::set_var(self.key, v),
            None => env::remove_var(self.key),
        }
    }
}

pub fn acquire_env_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::env_utils::test_support::acquire_env_lock()
}

pub fn make_pool() -> Arc<MemoryPool> {
    crate::optimize::global_pool()
}

pub fn mk_src_packet(id: u64, len: usize, pool: &Arc<MemoryPool>) -> FecPacket {
    let mut buf = pool.alloc();
    if buf.len() < len {
        // Allocate an exact-sized aligned buffer to satisfy test payload length
        let mut exact = AlignedBox::<[u8]>::slice_from_default(len, 64).unwrap_or({
            // Fallback: use pool buffer; FecPacket::new will upsize if needed
            buf
        });
        for (i, b) in exact.iter_mut().enumerate() {
            *b = (id as u8).wrapping_add(i as u8);
        }
        FecPacket::new(id, Some(exact), len, true, None, 0, Arc::clone(pool))
    } else {
        for (i, b) in buf.iter_mut().take(len).enumerate() {
            *b = (id as u8).wrapping_add(i as u8);
        }
        FecPacket::new(id, Some(buf), len, true, None, 0, Arc::clone(pool))
    }
}

pub fn drain_repairs(q: &mut VecDeque<FecPacket>) -> Vec<FecPacket> {
    let mut repairs = Vec::new();
    while let Some(pkt) = q.pop_front() {
        if !pkt.is_systematic {
            repairs.push(pkt);
        }
    }
    repairs
}

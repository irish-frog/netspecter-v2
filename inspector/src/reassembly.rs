use crate::tls::{HelloMetadata, HelloResult, inspect_client_hello};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize)]
pub struct Connection {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub connections: usize,
    pub bytes_per_connection: usize,
    pub total_bytes: usize,
    pub idle_ms: u64,
    pub lifetime_ms: u64,
    pub max_segments: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 4096,
            bytes_per_connection: 65_536,
            total_bytes: 64 * 1024 * 1024,
            idle_ms: 15_000,
            lifetime_ms: 30_000,
            max_segments: 128,
        }
    }
}

#[derive(Debug, Default)]
pub struct Counters {
    pub evicted: u64,
    pub expired: u64,
    pub conflicts: u64,
    pub invalid: u64,
    pub midstream: u64,
    pub completed: u64,
    pub segment_limit: u64,
}
struct Pending {
    start_sequence: u32,
    created: u64,
    last_seen: u64,
    data: Vec<u8>,
    present: Vec<u8>,
    contiguous: usize,
    finished: bool,
    segments: usize,
}
impl Pending {
    fn reserved(&self) -> usize {
        self.data.len() + self.present.len()
    }
    fn release(&mut self) {
        self.data = Vec::new();
        self.present = Vec::new();
        self.finished = true;
    }
}

pub struct Tracker {
    limits: Limits,
    flows: HashMap<Connection, Pending>,
    reserved: usize,
    pub counters: Counters,
}

pub struct Segment<'a> {
    pub sequence: u32,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload: &'a [u8],
}

impl Tracker {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            flows: HashMap::new(),
            reserved: 0,
            counters: Counters::default(),
        }
    }
    pub fn reserved_bytes(&self) -> usize {
        self.reserved
    }
    pub fn started_at(&self, key: &Connection) -> Option<u64> {
        self.flows.get(key).map(|flow| flow.created)
    }
    pub fn connection_count(&self) -> usize {
        self.flows.len()
    }
    fn remove(&mut self, key: &Connection) {
        if let Some(flow) = self.flows.remove(key) {
            self.reserved -= flow.reserved();
        }
    }
    pub fn expire(&mut self, now: u64) {
        let expired: Vec<_> = self
            .flows
            .iter()
            .filter(|(_, f)| {
                now.saturating_sub(f.last_seen) >= self.limits.idle_ms
                    || now.saturating_sub(f.created) >= self.limits.lifetime_ms
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.remove(&key);
            self.counters.expired += 1;
        }
    }
    fn evict_oldest(&mut self) -> bool {
        // Unique connection tuple breaks ties for deterministic eviction.
        let oldest = self
            .flows
            .iter()
            .min_by_key(|(k, f)| {
                (
                    f.last_seen,
                    f.created,
                    k.source,
                    k.destination,
                    k.source_port,
                    k.destination_port,
                )
            })
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.remove(&key);
            self.counters.evicted += 1;
            true
        } else {
            false
        }
    }
    pub fn ingest(
        &mut self,
        key: Connection,
        now: u64,
        segment: Segment<'_>,
    ) -> Option<HelloMetadata> {
        self.expire(now);
        if segment.rst {
            self.remove(&key);
            return None;
        }
        if segment.syn {
            let base = segment.sequence.wrapping_add(1);
            // Same-SYN retransmissions must not reset buffered evidence.
            if self
                .flows
                .get(&key)
                .is_some_and(|f| f.start_sequence != base)
            {
                self.remove(&key);
            }
            if !self.flows.contains_key(&key) {
                let size = self.limits.bytes_per_connection.min(65_536);
                let cost = size * 2;
                if size == 0 || self.limits.connections == 0 || cost > self.limits.total_bytes {
                    return None;
                }
                while self.flows.len() >= self.limits.connections
                    || self.reserved + cost > self.limits.total_bytes
                {
                    if !self.evict_oldest() {
                        return None;
                    }
                }
                self.flows.insert(
                    key.clone(),
                    Pending {
                        start_sequence: base,
                        created: now,
                        last_seen: now,
                        data: vec![0; size],
                        present: vec![0; size],
                        contiguous: 0,
                        finished: false,
                        segments: 0,
                    },
                );
                self.reserved += cost;
            }
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            if !segment.payload.is_empty() {
                self.counters.midstream += 1;
            }
            return None;
        };
        flow.last_seen = now;
        if flow.finished {
            if segment.fin {
                self.remove(&key);
            }
            return None;
        }
        if !segment.payload.is_empty() {
            flow.segments += 1;
            if flow.segments > self.limits.max_segments {
                self.reserved -= flow.reserved();
                flow.release();
                self.counters.segment_limit += 1;
                return None;
            }
        }
        let sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
        let offset = sequence.wrapping_sub(flow.start_sequence) as usize;
        let end = offset.checked_add(segment.payload.len());
        if !segment.payload.is_empty() && end.is_none_or(|end| end > flow.data.len()) {
            self.reserved -= flow.reserved();
            flow.release();
            self.counters.invalid += 1;
            return None;
        }
        for (index, byte) in segment.payload.iter().enumerate() {
            let position = offset + index;
            if flow.present[position] != 0 && flow.data[position] != *byte {
                self.reserved -= flow.reserved();
                flow.release();
                self.counters.conflicts += 1;
                return None;
            }
            flow.data[position] = *byte;
            flow.present[position] = 1;
        }
        let previous_contiguous = flow.contiguous;
        while flow.contiguous < flow.data.len() && flow.present[flow.contiguous] != 0 {
            flow.contiguous += 1;
        }
        if previous_contiguous == flow.contiguous {
            if segment.fin {
                self.remove(&key);
            }
            return None;
        }
        let result = inspect_client_hello(&flow.data[..flow.contiguous]);
        let metadata = match result {
            HelloResult::Incomplete => None,
            HelloResult::Invalid => {
                self.reserved -= flow.reserved();
                flow.release();
                self.counters.invalid += 1;
                None
            }
            HelloResult::Complete(metadata) => {
                self.reserved -= flow.reserved();
                flow.release();
                self.counters.completed += 1;
                Some(metadata)
            }
        };
        if segment.fin {
            self.remove(&key);
        }
        metadata
    }
}

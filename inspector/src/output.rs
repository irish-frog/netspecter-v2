use crate::{reassembly::Connection, tls::HelloMetadata};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Observation {
    pub schema_version: u8,
    pub event_type: &'static str,
    pub observed_at_unix_ms: u64,
    pub connection_started_at_unix_ms: u64,
    pub connection: Connection,
    #[serde(flatten)]
    pub hello: HelloMetadata,
}
impl Observation {
    pub fn new(connection: Connection, hello: HelloMetadata, started: u64, observed: u64) -> Self {
        Self {
            schema_version: 1,
            event_type: "tls_client_hello",
            observed_at_unix_ms: observed,
            connection_started_at_unix_ms: started,
            connection,
            hello,
        }
    }
    pub fn json_line(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[cfg(target_os = "linux")]
pub mod unix {
    use super::Observation;
    use std::{
        fs,
        io::{self, Write},
        os::unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
            mpsc::{self, SyncSender},
        },
        thread,
        time::{Duration, Instant},
    };

    pub struct Output {
        sender: SyncSender<Observation>,
        pub dropped: Arc<AtomicU64>,
    }
    fn connect_checked(path: &Path, expected_owner: u32) -> io::Result<UnixStream> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != expected_owner
            || metadata.mode() & 0o007 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe metadata socket ownership or permissions",
            ));
        }
        // The socket's directory must not be replaceable by the unprivileged sensor group.
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("socket needs a parent directory"))?;
        let directory = fs::symlink_metadata(parent)?;
        if !directory.is_dir() || directory.uid() != expected_owner || directory.mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe metadata socket directory",
            ));
        }
        let stream = UnixStream::connect(path)?;
        stream.set_write_timeout(Some(Duration::from_millis(250)))?;
        Ok(stream)
    }
    impl Output {
        pub fn spawn(path: PathBuf) -> Self {
            let (sender, receiver) = mpsc::sync_channel::<Observation>(1024);
            let dropped = Arc::new(AtomicU64::new(0));
            let failures = Arc::clone(&dropped);
            thread::spawn(move || {
                let mut connection = None;
                let mut retry_after = Instant::now();
                while let Ok(observation) = receiver.recv() {
                    if connection.is_none() && Instant::now() >= retry_after {
                        connection = connect_checked(&path, 0).ok();
                        retry_after = Instant::now() + Duration::from_secs(1);
                    }
                    let result = match (connection.as_mut(), observation.json_line()) {
                        (Some(stream), Ok(bytes)) => stream.write_all(&bytes),
                        _ => Err(io::Error::other("metadata consumer unavailable")),
                    };
                    if result.is_err() {
                        connection = None;
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            Self { sender, dropped }
        }
        pub fn send(&self, observation: Observation) {
            if self.sender.try_send(observation).is_err() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        #[test]
        fn missing_consumer_drops_bounded_output_without_blocking_producer() {
            use crate::{reassembly::Connection, tls::HelloMetadata};
            let output = Output::spawn(PathBuf::from(
                "/run/netspecter-nonexistent-test/metadata.sock",
            ));
            for _ in 0..10_000 {
                output.send(Observation::new(
                    Connection {
                        source: "192.0.2.1".parse().unwrap(),
                        destination: "203.0.113.1".parse().unwrap(),
                        source_port: 12345,
                        destination_port: 443,
                    },
                    HelloMetadata {
                        hostname: Some("example.com".into()),
                        ech_present: false,
                    },
                    1,
                    2,
                ));
            }
            assert!(output.dropped.load(Ordering::Relaxed) > 0);
        }
        #[test]
        fn slow_consumer_hits_write_timeout() {
            use std::os::unix::net::UnixListener;
            let directory =
                std::env::temp_dir().join(format!("netspecter-output-slow-{}", std::process::id()));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let socket = directory.join("socket");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
            let owner = fs::metadata(&directory).unwrap().uid();
            let mut stream = connect_checked(&socket, owner).unwrap();
            let (peer, _) = listener.accept().unwrap();
            let started = Instant::now();
            assert!(stream.write_all(&vec![0; 4 * 1024 * 1024]).is_err());
            assert!(started.elapsed() < Duration::from_secs(5));
            drop(peer);
            drop(stream);
            drop(listener);
            fs::remove_file(&socket).unwrap();
            fs::remove_dir(&directory).unwrap();
        }
        #[test]
        fn rejects_regular_files_and_world_accessible_socket() {
            use std::os::unix::net::UnixListener;
            let directory =
                std::env::temp_dir().join(format!("netspecter-output-test-{}", std::process::id()));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let file = directory.join("plain");
            fs::write(&file, b"test").unwrap();
            let owner = fs::metadata(&directory).unwrap().uid();
            assert!(connect_checked(&file, owner).is_err());
            let socket = directory.join("socket");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
            assert!(connect_checked(&socket, owner).is_err());
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
            assert!(connect_checked(&socket, owner).is_ok());
            drop(listener);
            fs::remove_file(&socket).unwrap();
            fs::remove_file(&file).unwrap();
            fs::remove_dir(&directory).unwrap();
        }
    }
}

//! The S3 half of `src/server/lib/storage.ts`.

use std::io;

use hyper::body::Incoming;

use crate::config::S3Config;
use crate::storage::{ByteStream, PutError, StoredObject};

pub struct S3Driver {}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "S3 storage is not available yet")
}

impl S3Driver {
    pub fn new(_config: &S3Config) -> S3Driver {
        S3Driver {}
    }

    pub async fn put(&self, _key: &str, _data: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }

    pub async fn put_stream(&self, _key: &str, _body: &mut Incoming, _limit: u64) -> Result<u64, PutError> {
        Err(PutError::Other(unsupported().to_string()))
    }

    pub async fn get(&self, _key: &str) -> io::Result<Option<StoredObject>> {
        Err(unsupported())
    }

    pub async fn read(&self, _key: &str, _range: Option<(u64, u64)>) -> io::Result<ByteStream> {
        Err(unsupported())
    }

    pub async fn remove(&self, _key: &str) -> io::Result<()> {
        Err(unsupported())
    }

    pub async fn copy(&self, _from: &str, _to: &str) -> io::Result<()> {
        Err(unsupported())
    }
}

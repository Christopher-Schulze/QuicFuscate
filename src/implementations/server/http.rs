use std::io;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub(crate) const MAX_CONCURRENT_CONNECTIONS: usize = 32;
pub(crate) const MAX_REQUEST_BYTES: usize = 8 * 1024;
pub(crate) const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(crate) enum RequestReadError {
    Io(io::Error),
    Incomplete,
    TimedOut,
    TooLarge,
}

pub(crate) async fn read_request(
    stream: &mut TcpStream,
) -> Result<Option<Vec<u8>>, RequestReadError> {
    let mut request = Vec::with_capacity(MAX_REQUEST_BYTES);
    let mut chunk = [0u8; 1024];

    loop {
        let read = tokio::time::timeout(REQUEST_READ_TIMEOUT, stream.read(&mut chunk)).await;
        match read {
            Err(_) => return Err(RequestReadError::TimedOut),
            Ok(Err(error)) => return Err(RequestReadError::Io(error)),
            Ok(Ok(0)) => {
                return if request.is_empty() {
                    Ok(None)
                } else {
                    Err(RequestReadError::Incomplete)
                };
            }
            Ok(Ok(read)) => {
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    return Ok(Some(request));
                }
                if request.len() >= MAX_REQUEST_BYTES {
                    return Err(RequestReadError::TooLarge);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn oversized_request_is_rejected_at_the_bounded_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let request = vec![b'x'; MAX_REQUEST_BYTES];
        let _ = client.write_all(&request).await;

        assert!(matches!(reader.await.unwrap(), Err(RequestReadError::TooLarge)));
    }
}

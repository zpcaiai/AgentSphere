//! Shared fail-closed response-body reader for production HTTP adapters.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BoundedBodyError {
    #[error("response body limit is invalid")]
    InvalidLimit,
    #[error("response body exceeds its configured limit")]
    BodyTooLarge,
    #[error("response body transport failed")]
    Transport,
}

/// Reads a response incrementally and stops before the accumulated body can exceed `maximum`.
///
/// `Content-Length` is only an early-rejection hint. Chunked responses and responses without a
/// length are subject to the same checked accumulator, so callers never aggregate an unbounded
/// body before enforcing their service-specific limit.
pub async fn read_bounded_body(
    mut response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, BoundedBodyError> {
    if maximum == 0 {
        return Err(BoundedBodyError::InvalidLimit);
    }
    let maximum_u64 = u64::try_from(maximum).map_err(|_| BoundedBodyError::InvalidLimit)?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum_u64)
    {
        return Err(BoundedBodyError::BodyTooLarge);
    }

    let mut body = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|_| BoundedBodyError::Transport)?;
        let Some(chunk) = chunk else {
            break;
        };
        checked_next_length(body.len(), chunk.len(), maximum)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn checked_next_length(
    current: usize,
    incoming: usize,
    maximum: usize,
) -> Result<usize, BoundedBodyError> {
    let next = current
        .checked_add(incoming)
        .ok_or(BoundedBodyError::BodyTooLarge)?;
    if next > maximum {
        return Err(BoundedBodyError::BodyTooLarge);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use std::time::Duration;

    fn serve_once(parts: Vec<Vec<u8>>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("test listener bind failed: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("test listener address failed: {error}"));
        let handle = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = [0_u8; 2_048];
            let _ = stream.read(&mut request);
            for part in parts {
                if stream.write_all(&part).is_err() {
                    return;
                }
            }
            let _ = stream.flush();
        });
        (format!("http://{address}/body"), handle)
    }

    async fn response_from(parts: Vec<Vec<u8>>) -> (reqwest::Response, JoinHandle<()>) {
        let (url, handle) = serve_once(parts);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|error| panic!("test client build failed: {error}"));
        let response = client
            .get(url)
            .send()
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        (response, handle)
    }

    #[test]
    fn rejects_overflow_and_first_chunk_over_limit() {
        assert_eq!(
            checked_next_length(0, 4_097, 4_096),
            Err(BoundedBodyError::BodyTooLarge)
        );
        assert_eq!(
            checked_next_length(usize::MAX, 1, usize::MAX),
            Err(BoundedBodyError::BodyTooLarge)
        );
    }

    #[test]
    fn accepts_exact_limit() {
        assert_eq!(checked_next_length(4_000, 96, 4_096), Ok(4_096));
    }

    #[tokio::test]
    async fn missing_content_length_is_bounded_by_actual_bytes() {
        let (response, handle) = response_from(vec![
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nexact".to_vec(),
        ])
        .await;
        assert_eq!(response.content_length(), None);
        assert_eq!(read_bounded_body(response, 5).await, Ok(b"exact".to_vec()));
        assert!(handle.join().is_ok());
    }

    #[tokio::test]
    async fn declared_length_over_limit_fails_before_a_short_body_is_trusted() {
        let (response, handle) = response_from(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 9999\r\nConnection: close\r\n\r\nshort".to_vec(),
        ])
        .await;
        assert_eq!(
            read_bounded_body(response, 8).await,
            Err(BoundedBodyError::BodyTooLarge)
        );
        assert!(handle.join().is_ok());
    }

    #[tokio::test]
    async fn chunked_body_crossing_limit_fails_before_append() {
        let (response, handle) = response_from(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec(),
            b"4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n".to_vec(),
        ])
        .await;
        assert_eq!(
            read_bounded_body(response, 7).await,
            Err(BoundedBodyError::BodyTooLarge)
        );
        assert!(handle.join().is_ok());
    }

    #[tokio::test]
    async fn chunked_body_at_exact_limit_is_accepted() {
        let (response, handle) = response_from(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec(),
            b"4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n".to_vec(),
        ])
        .await;
        assert_eq!(
            read_bounded_body(response, 8).await,
            Ok(b"abcdefgh".to_vec())
        );
        assert!(handle.join().is_ok());
    }

    #[tokio::test]
    async fn zero_limit_fails_closed() {
        let (response, handle) = response_from(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
        ])
        .await;
        assert_eq!(
            read_bounded_body(response, 0).await,
            Err(BoundedBodyError::InvalidLimit)
        );
        assert!(handle.join().is_ok());
    }

    #[tokio::test]
    async fn truncated_declared_body_is_a_transport_failure() {
        let (response, handle) = response_from(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nabcd".to_vec(),
        ])
        .await;
        assert_eq!(
            read_bounded_body(response, 8).await,
            Err(BoundedBodyError::Transport)
        );
        assert!(handle.join().is_ok());
    }
}

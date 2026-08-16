use tokio::io::{AsyncBufRead, AsyncRead};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

// Enum to represent different types of streams (TLS or Plain)
#[derive(Debug)]
pub enum StreamType {
    Tls(tokio::io::BufReader<TlsStream<TcpStream>>),
    Plain(tokio::io::BufReader<TcpStream>),
}

impl AsyncRead for StreamType {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamType::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            StreamType::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncBufRead for StreamType {
    fn poll_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<&[u8]>> {
        match self.get_mut() {
            StreamType::Tls(s) => std::pin::Pin::new(s).poll_fill_buf(cx),
            StreamType::Plain(s) => std::pin::Pin::new(s).poll_fill_buf(cx),
        }
    }

    fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
        match self.get_mut() {
            StreamType::Tls(s) => std::pin::Pin::new(s).consume(amt),
            StreamType::Plain(s) => std::pin::Pin::new(s).consume(amt),
        }
    }
}

impl StreamType {
    pub fn is_tls(&self) -> bool {
        matches!(self, StreamType::Tls(_))
    }
}

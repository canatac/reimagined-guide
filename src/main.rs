use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 512];
    stream.read(&mut buffer).unwrap();

    let message = String::from_utf8_lossy(&buffer[..]);

    if message.starts_with("HELO") || message.starts_with("EHLO") {
        stream.write(b"250 Hello\r\n").unwrap();
    } else if message.starts_with("MAIL FROM:") {
        stream.write(b"250 OK\r\n").unwrap();
    } else if message.starts_with("RCPT TO:") {
        stream.write(b"250 OK\r\n").unwrap();
    } else if message.starts_with("DATA") {
        stream.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n").unwrap();
    } else if message == ".\r\n" {
        stream.write(b"250 OK\r\n").unwrap();
    } else {
        stream.write(b"500 Syntax error, command unrecognized\r\n").unwrap();
    }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:2525").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                handle_client(stream);
            }
            Err(e) => { println!("Error: {}", e); }
        }
    }
}
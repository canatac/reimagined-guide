# Rust SMTP Server Documentation

## 1. Introduction

### 1.1 Purpose of the Project
This project aims to create a robust, secure, and efficient SMTP server implemented in Rust. The server is designed to handle both plain text and TLS-encrypted connections, providing a flexible solution for email handling.

### 1.2 Key Features
- Support for both plain text and TLS-encrypted connections
- Asynchronous I/O operations using Tokio
- SMTP protocol compliance
- Basic authentication mechanisms (AUTH LOGIN and AUTH PLAIN)
- Email storage in a local directory
- Configurable through environment variables

### 1.3 Technology Stack
- Rust programming language
- Tokio for asynchronous runtime
- Rustls for TLS implementation
- Base64 for encoding/decoding
- Chrono for timestamp generation
- Mailparse for email parsing
- Dotenv for environment variable management

## 2. System Architecture

### 2.1 High-Level Overview
The SMTP server is built as a multi-threaded application that listens on two ports: one for plain text connections and another for TLS connections. It uses Tokio for asynchronous I/O operations, allowing it to handle multiple client connections efficiently.

### 2.2 Component Diagram
[A component diagram would be inserted here, showing the main components of the system: TLS Listener, Plain Text Listener, Email Processor, Authentication Handler, and Storage Manager]

### 2.3 Data Flow
1. Client connects to the server (plain text or TLS)
2. Server authenticates the client (if required)
3. Client sends email data
4. Server processes and stores the email
5. Server sends confirmation to the client

## 3. Implementation Details

### 3.1 Core Server Implementation

#### 3.1.1 TLS and Plain Text Connections
The server uses two separate TCP listeners: one for TLS connections and one for plain text. The TLS listener uses Rustls for secure connections, while the plain text listener allows for unencrypted communication.

#### 3.1.2 Asynchronous I/O with Tokio
Tokio is used to handle asynchronous I/O operations, allowing the server to handle multiple connections concurrently without blocking.

#### 3.1.3 SMTP Protocol Handling
The server implements basic SMTP commands such as HELO/EHLO, MAIL FROM, RCPT TO, DATA, and QUIT. It processes these commands in the `process_command` function.

### 3.2 Email Processing

#### 3.2.1 Parsing Incoming Emails
The server uses the `mailparse` crate to parse incoming emails, extracting relevant information such as sender, recipient, subject, and body.

#### 3.2.2 Email Storage System
Emails are stored in a local directory ("./emails") as .eml files. Each file is named with a timestamp and the recipient's email address.

### 3.3 Authentication Mechanisms

#### 3.3.1 AUTH LOGIN
The server supports the AUTH LOGIN mechanism, which involves a base64-encoded username and password exchange.

#### 3.3.2 AUTH PLAIN
The AUTH PLAIN mechanism is also supported, allowing for a single-step authentication process.

### 3.4 Certificate Handling
The server loads TLS certificates and private keys from files specified in the environment variables. It uses these for establishing TLS connections.

### 3.5 Error Handling and Logging
Errors are logged using the `log` crate, with different severity levels for various types of errors. The server attempts to gracefully handle errors and continue operation where possible.

## 4. Configuration

### 4.1 Server Configuration

#### 4.1.1 TLS Settings
TLS settings are configured using environment variables, including paths to certificate and key files.

#### 4.1.2 Listening Ports
The server listens on two ports: one for TLS connections and one for plain text. These are configurable via environment variables.

### 4.2 Environment Variables
- `SMTP_TLS_ADDR`: Address and port for TLS connections
- `SMTP_PLAIN_ADDR`: Address and port for plain text connections
- `CERT_PATH`: Path to the TLS certificate file
- `KEY_PATH`: Path to the TLS private key file
- `SMTP_USERNAME`: Username for authentication
- `SMTP_PASSWORD`: Password for authentication

### 4.3 Certificates and Keys
The server requires a valid TLS certificate and private key for secure connections. These should be obtained from a trusted certificate authority and placed in a secure location on the server.

## 5. Deployment

### 5.1 System Requirements
- Rust 1.54 or later
- Sufficient disk space for email storage
- Network access for incoming connections

### 5.2 Installation Process
1. Clone the repository
2. Run `cargo build --release`
3. Set up the required environment variables
4. Ensure certificate and key files are in place

### 5.3 Running the Server
Execute the compiled binary, ensuring all environment variables are set correctly.

## 6. Testing

### 6.1 Unit Tests
[Details about unit tests would be added here]

### 6.2 Integration Tests
[Details about integration tests would be added here]

### 6.3 Load Testing
[Information about load testing procedures and results would be added here]

## 7. Security Considerations

### 7.1 TLS Implementation
The server uses Rustls for TLS, which is designed to be a secure-by-default TLS library.

### 7.2 Authentication Best Practices
Passwords are not stored in plain text. Consider implementing more secure authentication methods for production use.

### 7.3 Known Limitations and Risks
- The current implementation stores emails as files, which may not be suitable for high-volume production environments.
- There's no spam filtering or advanced security features implemented.

## 8. Performance Optimization

### 8.1 Concurrency Model
The server uses Tokio's async runtime to handle multiple connections concurrently.

### 8.2 Resource Management
[Details about how the server manages resources like memory and file handles would be added here]

## 9. Maintenance and Monitoring

### 9.1 Logging and Diagnostics
The server uses the `log` crate for logging. Consider implementing more advanced logging and monitoring for production use.

### 9.2 Backup and Recovery
[Information about backup procedures for stored emails would be added here]

### 9.3 Updating and Upgrading
To update the server, pull the latest changes from the repository and rebuild. Ensure to test thoroughly after any updates.

## 10. Future Enhancements

### 10.1 Planned Features
- Implement DKIM signing
- Add support for SMTP extensions like SMTPUTF8
- Implement a more robust storage solution

### 10.2 Potential Improvements
- Enhance error handling and recovery mechanisms
- Implement more comprehensive logging and monitoring
- Add support for plugins or extensions

## 11. Troubleshooting Guide

### 11.1 Common Issues and Solutions
[A list of common issues and their solutions would be added here]

### 11.2 Debugging Techniques
[Information about debugging techniques specific to this server would be added here]

## 12. API Documentation (if applicable)

### 12.1 External Interfaces
[If the server exposes any APIs, they would be documented here]

### 12.2 Internal APIs
[Documentation for any internal APIs or important functions would be added here]

## 13. Glossary of Terms
- SMTP: Simple Mail Transfer Protocol
- TLS: Transport Layer Security
- AUTH LOGIN: An SMTP authentication method using base64-encoded credentials
- AUTH PLAIN: An SMTP authentication method using a single base64-encoded string

## 14. References and Resources
- [Rust Documentation](https://doc.rust-lang.org/book/)
- [Tokio Documentation](https://tokio.rs/docs/overview/)
- [SMTP RFC](https://tools.ietf.org/html/rfc5321)
- [Rustls Documentation](https://docs.rs/rustls/)
## Team 14 : 
- Vatsal Gupta (2024201065) 
- Vaibhav Jain (2024201023)

# Secure Socket Communication System

A client-server application implementing secure communication using DES encryption, Diffie-Hellman key exchange, and HMAC message authentication.

## Features

- TCP socket-based client-server communication
- Diffie-Hellman key exchange for secure key generation
- Double DES encryption for data confidentiality
- HMAC (SHA-256) for message integrity
- Session token-based authentication
- Numeric data aggregation on server side

## Components

### 1. Server (server1.py)
- Handles multiple client connections using threads
- Implements Diffie-Hellman key exchange
- Generates and manages session tokens
- Validates incoming messages using HMAC
- Aggregates numeric data from clients
- Sends encrypted responses back to clients

### 2. Client (client1.py)
- Connects to server using TCP sockets
- Participates in Diffie-Hellman key exchange
- Encrypts outgoing messages using Double DES
- Generates HMAC for message integrity
- Validates server responses
- Handles session tokens

### 3. Cryptography Module (des_crypto.py)
- Implements Diffie-Hellman key generation
- Provides simplified DES encryption/decryption
- Implements Double DES for enhanced security
- Handles HMAC generation and verification

## Security Features

- *Key Exchange*: Secure key generation using Diffie-Hellman algorithm
- *Encryption*: Double DES encryption for message confidentiality
- *Message Integrity*: HMAC-SHA256 for detecting message tampering
- *Session Management*: Unique session tokens for client authentication
- *Data Validation*: Input validation to prevent injection attacks

## Installation

1. Ensure Python 3.x is installed
2. Install required dependencies:
```bash
pip install cryptography
```
3. start server 
```bash
python server.py 
```
4. start client
```bash
python client.py
```
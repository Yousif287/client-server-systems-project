# Secure Client–Server Messaging System

This project is a Python-based secure messaging application that allows multiple clients to communicate over a network using encrypted communication. It implements a hybrid cryptographic approach where RSA is used for key exchange and AES is used for message encryption.

The system is designed to demonstrate fundamental client–server communication concepts along with practical cryptographic techniques.

Features:
- Encrypted client–server communication over UDP
- RSA-based key exchange for secure session setup
- AES encryption for message confidentiality
- Support for multiple concurrent clients
- Server-side message relaying with per-client encryption

System Architecture:

Connection Workflow:
1. Handshake
   The client initiates a connection and the server acknowledges it to establish a session.

2. Key Exchange
   The client sends an RSA public key. The server generates an AES session key, encrypts it with the client’s public key, and sends it back.

3. User Registration
   The client sends a username which the server associates with the session and AES key.

4. Encrypted Messaging
   Clients send AES-encrypted messages to the server. The server relays messages to other connected clients, encrypting each message using the recipient’s AES key.

Cryptographic Design:
- RSA (2048-bit) is used for secure exchange of AES session keys.
- AES-128 in CBC mode is used to encrypt chat messages.
- A random IV is generated per message to prevent ciphertext reuse.
- Base64 encoding is used to safely transmit encrypted data over UDP.

Project Structure:
client.py        Client-side logic
server.py        Server-side logic
crypto_utils.py  Cryptographic utilities

Requirements:
- Python 3.7 or newer
- pycryptodome

To install dependencies:
pip install pycryptodome

Running the application:

Start the server:
python server.py

Start a client in a separate terminal:
python client.py

Multiple clients can be launched in separate terminals to simulate concurrent communication.

Limitations:
- Designed for local network testing
- UDP-based communication without persistent storage
- Intended as a proof-of-concept for secure messaging protocols

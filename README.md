# COMPE 560 Homework

## Description

This assignment is a simple and secure chat application that lets multiple users talk to each other over a network using UDP. Every message sent in the chat is protected using encryption. First, when a user connects, the server and client securely exchange encryption keys using RSA. After that, every chat message is encrypted using AES, which is fast and keeps the conversation private. The server collects messages, adds the sender’s username, and sends them out to all other users. Each message is encrypted again before being sent, so only the intended clients can read them.


### Work flow

1. **Handshake**  
    Client sends `SYN`  
    Server responds with `SYN-ACK`  
    Client sends `ACK`

2. **Key Exchange**  
    Client sends RSA Public Key  
    Server generates AES Key, encrypts with RSA Public Key, and sends back

3. **Username Exchange**  
    Client sends username  
    Server saves username and AES key for future communication

4. **Chat**  
    Clients can now send AES-encrypted messages to server  
    Server relays each message to other clients encrypted with their AES keys


### Dependencies

Python 3.7+
- Install required library:
  pip install pycryptodome

## How to Run (I am using Visual Studio Code so this might be different in case you try to run this on a different IDE)

### 1. Start the Server (in a terminal)

Type into the newly opened terminal:

python server.py

## If you don't type this in, then Visual Studio Code can't actually run multiple terminals at the same time, which you do need to do in order to communicate between 2 clients, so don't just run terminals using the run button. You have to run them manually!

After running server.py, you should see "Server started on port 12345" which is a sign that the server is indeed running. 

## 2. Start a Client (in another terminal)

Type into the newly opened terminal:

python client.py

Enter your username when prompted, and then feel free to chat from terminal to terminal (client to client in this scenario but you will have to open up new terminals if you want to talk to other users)

## Summary of cryptographic design choices

## Cryptographic Design

RSA 2048-bit - Used to securely exchange AES symmetric keys.
AES 128-bit CBC mode - Used to encrypt chat messages.
Random IV - Used per message for security.
Base64 - Used to send encrypted data safely over UDP.

## Design Decisions

This project is based on the provided starter code.

Only additions that were made:
    Adding handshake SYN and ACK when connection is established locally
    Adding username handling for cleaner message appearances between terminals

## Limitations and Assumptions.

    - Having to cycle between termminals back and forth can be a bit redundant, although necessary. 
    - Only able to run on Local Host (127.0.0.1)
"""
Server-side application for the secure chat project.
Receives client connections, performs handshake and RSA/AES key exchange,
and relays AES-encrypted chat messages between connected clients.

Workflow:
- Perform handshake with client to verify they are ready.
- Wait for client RSA public key.
- Generate AES key and send it encrypted with RSA.
- Receive username and store AES key and username for the client.
- Receive AES-encrypted messages, decrypt them, prepend username, and broadcast
  to other clients encrypted with their respective AES keys.
"""

import socket
import threading
import base64
from crypto_utils import generate_aes_key, encrypt_with_rsa, decrypt_with_aes, encrypt_with_aes

clients = {}  # addr (aes_key, username)
client_keys = {}  # addr rsa public key
client_states = {}  # addr "handshake", "rsa_sent", "ready"

def handle_messages(sock):
    """
    Main loop to handle incoming client messages and connection setup.

    - For new clients: perform handshake, RSA key exchange, and receive username.
    - For existing clients: decrypt received messages, prepend username, and broadcast.

    Args:
        sock (socket.socket): The UDP socket listening for client messages.
    """
    while True:
        data, addr = sock.recvfrom(4096)
        message = data.decode(errors="ignore")  # avoid errors on non-text data

        #  [ HANDSHAKE START ] 
        if addr not in client_states:
            # New client → waiting for SYN
            if message == "SYN":
                sock.sendto(b"SYN-ACK", addr)
                client_states[addr] = "handshake"
                continue
        elif client_states[addr] == "handshake":
            # Waiting for ACK to complete handshake
            if message == "ACK":
                client_states[addr] = "awaiting_rsa"
                print(f"Handshake completed with {addr}")
                continue
            else:
                continue
        elif client_states[addr] == "awaiting_rsa":
            # First message after handshake → RSA public key
            rsa_pub_key = base64.b64decode(data)
            aes_key = generate_aes_key()
            encrypted_key = encrypt_with_rsa(rsa_pub_key, aes_key)
            sock.sendto(base64.b64encode(encrypted_key), addr)

            client_keys[addr] = rsa_pub_key
            client_states[addr] = ("awaiting_username", aes_key)
            continue
        elif isinstance(client_states[addr], tuple) and client_states[addr][0] == "awaiting_username":
            # Second message → username
            aes_key = client_states[addr][1]
            username = message

            clients[addr] = (aes_key, username)
            client_states[addr] = "ready"
            print(f"Key exchanged with {addr}, Username: {username}")
            continue
        #  [ HANDSHAKE END ]

        if addr in clients:
            sender_aes_key, sender_username = clients[addr]

            # Decrypt incoming message
            decrypted_message = decrypt_with_aes(sender_aes_key, message)

            # Prepare message with username
            message_to_send = f"{sender_username}: {decrypted_message}"

            # Broadcast to all other clients
            for client_addr, (client_aes_key, client_username) in clients.items():
                if client_addr != addr:
                    encrypted_message = encrypt_with_aes(client_aes_key, message_to_send)
                    sock.sendto(encrypted_message.encode(), client_addr)

def main():
    """
    Initialize the UDP server and start listening for client messages.

    Binds to localhost on port 12345 and starts the message handling loop.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("localhost", 12345))
    print("Server started on port 12345")
    handle_messages(sock)

if __name__ == "__main__":
    main()

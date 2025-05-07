"""
Client-side application for the secure chat project.
Connects to the server, performs RSA/AES key exchange, and allows
sending and receiving encrypted messages in a chat format.

Workflow:
- Perform handshake to verify server is alive.
- Generate RSA keys and send public key to server.
- Receive AES key (encrypted with RSA) and decrypt it.
- Send username to server.
- Send and receive AES-encrypted chat messages.
"""

import socket
import threading
import base64
from crypto_utils import (
    generate_rsa_keypair, decrypt_with_rsa,
    encrypt_with_aes, decrypt_with_aes
)

aes_key = None

def receive_messages(sock, private_key):
    """
    Thread function to receive and process incoming messages from the server.

    If AES key is not yet received, decrypts it using RSA and stores it.
    Otherwise, decrypts AES-encrypted messages and displays them.

    Args:
        sock (socket.socket): The UDP socket connected to the server.
        private_key (bytes): The RSA private key for decrypting AES key.
    """
    global aes_key
    while True:
        data, _ = sock.recvfrom(4096)
        if aes_key is None:
            encrypted_key = base64.b64decode(data)
            aes_key = decrypt_with_rsa(private_key, encrypted_key)
            print("Received and decrypted AES key.")
        else:
            try:
                decrypted = decrypt_with_aes(aes_key, data.decode())
                print(decrypted)
            except:
                pass

def main():
    """
    Main function for client operation.

    - Creates UDP socket and connects to server.
    - Performs handshake to ensure server is alive.
    - Sends RSA public key and username.
    - Starts receiver thread to handle incoming messages.
    - Reads user input, encrypts with AES, and sends to server.
    """
    global aes_key
    server_addr = ("localhost", 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # [ HANDSHAKE START ]
    # Send SYN to server
    sock.sendto(b"SYN", server_addr)

    # Wait for SYN-ACK
    response, _ = sock.recvfrom(4096)
    if response.decode() == "SYN-ACK":
        # Send ACK to complete handshake
        sock.sendto(b"ACK", server_addr)
        print("Handshake complete with server.")
    else:
        print("Handshake failed. Exiting.")
        return
    #  [ HANDSHAKE END ] 

    # Generate RSA keys and send public key
    private_key, public_key = generate_rsa_keypair()
    sock.sendto(base64.b64encode(public_key), server_addr)

    # Send username after public key
    username = input("Enter your username: ")
    sock.sendto(username.encode(), server_addr)

    # Start thread to receive messages
    threading.Thread(target=receive_messages, args=(sock, private_key), daemon=True).start()

    while True:
        msg = input()
        if aes_key:
            encrypted = encrypt_with_aes(aes_key, msg)
            sock.sendto(encrypted.encode(), server_addr)
        else:
            print("Waiting for key exchange to complete...")

if __name__ == "__main__":
    main()

# Server public key = P
# Client public key = G

from cryptography.fernet import Fernet
from socket import socket, gethostname, AF_INET, SOCK_STREAM
from _thread import start_new_thread
from sys import argv
from shared import handle_message, generate_random_number, send_message, extract_key, recieve, send

def key_exchange(sock: socket, keys: tuple) -> int:
    # KEYS = (G, P, private)
    public, private = keys[0], keys[1]
    # Create the key to be exchanged
    print("Initiating key exchange with client")
    send(sock, "KEYEXCHANGE:START")
    print("Waiting for client public key")
    client_public_key = recieve(sock)
    client_public_key = extract_key(client_public_key)
    # once we have the clients public key generate our exchange key
    print("Generating exchange key")
    ex_key = pow(client_public_key, private, public)
    print("Sending our public key")
    send(sock, f"KEYEXCHANGE:{public}")
    print("Waiting for client exchange key")
    key = recieve(sock)
    client_ex_key = extract_key(key)
    print("Recieved the client's exchange key")
    print("Sending our key")
    send(sock, f"KEYEXCHANGE:{ex_key}")
    print("Generating shared secret key")
    return pow(client_ex_key, private, public)

if __name__ == "__main__":
    if len(argv) < 2:
        print("Too few arguments")
        exit(1)
    SERVER_PORT = int(argv[1])

    # Set up the socket 
    sock = socket(AF_INET, SOCK_STREAM)

    # Generate all the keys used for encryption
    public_key = generate_random_number(32)
    private_key = generate_random_number(32)
    SECRET_KEY = None

    # start socket connection and listen for clients
    print("Starting my client\n Waiting for Connection")

    sock.bind((gethostname(), SERVER_PORT))
    sock.listen(5)

    client, addr = sock.accept()

    # Right after connection handle key exchange process

    SECRET_KEY = key_exchange(client, (public_key, private_key))

    print("Handling incoming messages")

    start_new_thread(handle_message, (client, addr, SECRET_KEY))

    send_message(client, SECRET_KEY)
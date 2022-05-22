from cryptography.fernet import Fernet
from socket import socket, gethostname, AF_INET, SOCK_STREAM
from _thread import start_new_thread
from sys import argv
from shared import handle_message, generate_random_number, send_message, extract_key, recieve, send

if __name__ == "__main__":
    if len(argv) < 2:
        print("Too few arguments\n Example: server.py 3001 or client.py 3001")
        exit(1)
    CONNECT_PORT = int(argv[1])

    sock = socket(AF_INET, SOCK_STREAM)

    # Generate all the keys used for encryption
    public_key = generate_random_number(32)
    private_key = generate_random_number(32)
    SECRET_KEY = None
    
    print(f"Connecting to {gethostname()}")

    sock.connect((gethostname(), CONNECT_PORT))

    print("Connected!")

    print("Waiting for key exchange to be initiated...")

    while True:
        msg = recieve(sock)

        if msg == "KEYEXCHANGE:START":
            print("Key exchange started")
            print("Sending public key")
            send(sock, f"KEYEXCHANGE:{public_key}")
            print("Receiving server's public key")
            server_public_key = recieve(sock)
            server_public_key = extract_key(server_public_key)
            print("Generating exchange key: ")
            ex_key = pow(public_key, private_key, server_public_key)
            print("Sending exchange key: ")
            send(sock, f"KEYEXCHANGE:{ex_key}")
            print("Waiting for server key")
            key = recieve(sock)
            server_key = extract_key(key)
            print("Received server key")
            print("Generating secret key")
            SECRET_KEY = pow(server_key, private_key, server_public_key)
            print("Generated")
            break
    
    print("Handling incoming messages")

    start_new_thread(handle_message, (sock, gethostname(), SECRET_KEY))

    send_message(sock, SECRET_KEY)
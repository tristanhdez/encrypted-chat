from os import urandom
from cryptography.fernet import Fernet
from socket import socket
from sys import byteorder
from base64 import encodebytes

def handle_message(client_sock: socket, addr: str, secret: int) -> None:
    while True:
        decrypt_client = Fernet(encodebytes(secret.to_bytes(32, byteorder)))
        msg = client_sock.recv(4096)
        msg = decrypt_client.decrypt(msg)
        if not msg:
            break
        print(f"\r{addr}: {msg.decode('utf-8')}")
        print("\n-->", end="")
    print("\rConnection closed\n")
    client_sock.close()

def generate_random_number(size: int) -> int:
    return int.from_bytes(urandom(size), byteorder)

def send_message(client_sock: socket, secret: int) -> None:
    while True:
        msg = input("-->")
        encrypt_client = Fernet(encodebytes(secret.to_bytes(32, byteorder)))
        try:
            client_sock.sendall(encrypt_client.encrypt(msg.encode("utf-8")))
        except:
            print("\rCannot send message")
            break
        

def extract_key(msg: str) -> int:
    return int(msg.split(":")[1].strip())

def recieve(sock: socket) -> str:
    msg = sock.recv(4096).decode("utf-8")
    return msg

def send(sock: socket, message: str) -> None:
    sock.sendall(message.encode("utf-8"))
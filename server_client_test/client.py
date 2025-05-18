import socket

HOST = "127.0.0.1"  # Change to your server's IP
PORT = 9001
import time

import secrets
import string


def generate_random_string(length):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    num = 0 
    #while client:
    #random_string = generate_random_string(10)
    for num in range(5000):
        random_string = str(num)+'\n'
        client.sendall(random_string.encode())

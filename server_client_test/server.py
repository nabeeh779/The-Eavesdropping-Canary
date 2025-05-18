import socket

HOST = "0.0.0.0"  # Listen on all available interfaces
PORT = 9001       # Choose a port in the target range

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()
    print(f"Listening on {HOST}:{PORT}...")

    conn, addr = server.accept()
    with conn:
        print(f"Connection from {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode(errors='ignore')}")  # Print received data

import socket
import os
import time

HOST = '192.168.164.139'
PORT = 8080
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096

filename = "sockettextspam.txt"
filesize = os.path.getsize(filename)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.send(f"{filename}{SEPARATOR}{filesize}".encode())

    with open(filename, "rb") as f:
        while True:
            data = f.read(BUFFER_SIZE)
            if not data:
                break
            s.send(data)
            print("sending..")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("", PORT))
    s.listen()
    conn, addr = s.accept()
    
    with conn:
        data = conn.recv(BUFFER_SIZE).decode()

        print(data)


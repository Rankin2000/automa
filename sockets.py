import socket
import os
import time

HOST = '192.168.164.140'
PORT = 8080
BUFFER_SIZE = 4096

def send(filename):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(filename.encode('utf-8'))
            print(str(filename.encode('utf-8')))

            with open(filename, "rb") as f:
                while True:
                    data = f.read(BUFFER_SIZE)
                    if not data:
                        break
                    s.send(data)
                    print("sending..")
    except:
        print("Can't connect to Virtual Machine")

        raise
def receive():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", PORT))
        s.listen()
        conn, addr = s.accept()
    
        with conn:
            data = conn.recv(BUFFER_SIZE).decode()

            print(data)

    return data

if __name__ == "__main__":
    send("Sample2.exe")

import socket
import os
import time

HOST = '192.168.56.2'
PORT = 8080
BUFFER_SIZE = 4096

def send(filename):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(filename.encode())
            response = s.recv(BUFFER_SIZE)
            if response:
                with open(filename, "rb") as f:
                    while True:
                        data = f.read(BUFFER_SIZE)
                        if not data:
                            break
                        s.sendall(data)
                        print("Sending..")
                #print(PID)

                return True
            else:
                return False
    except ConnectionRefusedError: 
        print("Can't connect to Virtual Machine")
        return False

def receive():
    fulldata = ""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", PORT))
        s.listen()
        conn, addr = s.accept()
    
        with conn:
            while True:
                data = conn.recv(BUFFER_SIZE).decode()

                if not data:
                    break
                fulldata += data
    return fulldata

if __name__ == "__main__":
    while not send("helloworld.exe"):
        pass

    json = receive()
    f = open("pesieve.json", "w")
    f.write(json)
    f.close()
    print(json)
    time.sleep(1)



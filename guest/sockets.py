import socket
import analyser
import time
HOST = '192.168.56.1' #Host IP
PORT = 8080
BUFFER_SIZE = 4096


def send(file):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #while True:
        #    try:
        #        s.connect((HOST, PORT))
        #        break
        #    except:
        #        pass
        #s.sendall(data.encode())

        s.connect((HOST, PORT))
        with open(file, "rb") as f:
            while True:
                data = f.read(BUFFER_SIZE)
                if not data:
                    break
                s.sendall(data)
    return True

def receive():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', PORT))
        s.listen()
        conn, addr = s.accept()

        with conn:
            print('Connected by', addr)

            filename = conn.recv(BUFFER_SIZE).decode()
            conn.sendall(filename.encode())
            
            with open(filename, "wb") as f:
                while True:
                    
                    data = conn.recv(BUFFER_SIZE)
        
                    if not data:
                        #analyse
                        break
                        print("analysing..")
                        
                    f.write(data)
                    #conn.sendall("Received".encode())
                    print("writing...")

            

            
            return filename
    
            

while True:
    filename = False
    while not filename:
        try:
            filename = receive()
        except UnicodeDecodeError:
            print("Odd Unicode bug, Trying again")
        except:
            raise
    analyser.analyse(filename)
    send("pe-sieve.json")

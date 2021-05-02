import socket
import analyser
import os
HOST = '192.168.56.1' #Host IP
PORT = 8080
BUFFER_SIZE = 4096

#Send file back to host
def send(file):
    #Create socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #Connect
        s.connect((HOST, PORT))
        with open(file, "rb") as f:
            #Read and send data of BUFFER_SIZE until none then break
            while True:
                data = f.read(BUFFER_SIZE)
                if not data:
                    break
                s.sendall(data)
    #Return that sending file was successful
    return True
    
#Receive file from host
def receive():
    #Create socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #Bind socket
        s.bind(('', PORT))
        #Listen
        s.listen()
        #Accept connection
        conn, addr = s.accept()

        with conn:
            print('Connected by', addr)
            #Receive filename
            filename = conn.recv(BUFFER_SIZE).decode()
            #Return filename as confirmation
            conn.sendall(filename.encode())
                        
            with open(filename, "wb") as f:
                #Recieve and write data of BUFFER_SIZE until none left then break
                while True:
                    data = conn.recv(BUFFER_SIZE)
                
                    if not data:
                        break
                    
                    f.write(data)
                    print("writing...")
    return filename
                
#Loop endlessly
while True:
    #While filename is false try to recieve filename from host
    filename = False
    while not filename:
        try:
            filename = receive()
        except:
            raise
    #Send file to analyser to analyse
    analyser.analyse(filename)

    #If pe-sieve.json is of 0 then pe-sive failed so return "failed"
    if os.stat("pe-sieve.json").st_size == 0:
        print("pe-sieve failed.")
        with open("pe-sieve.json", "w") as f:
            f.write("failed")
    #Else return pe-seive results
    else:
        send("pe-sieve.json")
    

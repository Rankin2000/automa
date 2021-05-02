import socket
import os
import time

HOST = '192.168.56.2'
PORT = 8080
BUFFER_SIZE = 4096

#Send file to VM
def send(filename):
    #Attempt to create socket
    try:
        #Create socket and set various options
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #Try to connect to HOST and PORT variables
        s.connect((HOST, PORT))
        #Send filename
        s.send(filename.encode())
        #Get response confirming transfer
        response = s.recv(BUFFER_SIZE)
        #If VM responded send file data
        if response:
            with open(filename, "rb") as f:
                #Send data of BUFFER_SIZE until no data left then break
                while True:
                    data = f.read(BUFFER_SIZE)
                    if not data:
                        break
                    s.sendall(data)
                    print("Sending..")
        s.close()
    #VM Refused connection
    except ConnectionRefusedError: 
        print("Can't connect to Virtual Machine")

#Recieve files from VM
def receive():
    #Initialise full data variable
    fulldata = ""
    #Create socket and set various options
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(20)
    #Bind to host not VM
    s.bind(("", PORT))
    #Listen for connection
    s.listen()
    #Accept connection
    conn, addr = s.accept()
    with conn:
        #Receive data of BUFFER_SIZE untill none left then break
        while True:
            data = conn.recv(BUFFER_SIZE).decode()
            if not data:
                break        
            #Add current data received to fulldata
            fulldata += data
    #Close connection
    s.close()
    #Return full file
    return fulldata


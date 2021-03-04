import socket
import os
import analyser
HOST = '192.168.164.138' #Host IP
PORT = 8080
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"


    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('', PORT))
    s.listen()
    conn, addr = s.accept()

    with conn:
        print('Connected by', addr)
        
        data = conn.recv(BUFFER_SIZE).decode()
        filename, filesize = data.split(SEPARATOR)
        
        filename = os.path.basename(filename)
        filesize = int(filesize)

       
        
        with open(filename + "server", "wb") as f:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    #analyse
                    
                    print("analysing..")
                    break
                
                #conn.send(str('1').encode())
                f.write(data)
                #conn.sendall("COMPLETE".encode())
                print("writing...")
                
        

        print("finished")


        #with open(filename + "server", "r") as f:            
        #conn.send(filename.encode())
    
        
        
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    while True:
        try:
            s.connect((HOST, PORT))
            break
        except:
            pass

    
    s.send(analyser.analyse(filename).encode())


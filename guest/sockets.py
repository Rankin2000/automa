import socket
import analyser
HOST = '192.168.164.138' #Host IP
PORT = 8080
BUFFER_SIZE = 4096



    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('', PORT))
    s.listen()
    conn, addr = s.accept()

    with conn:
        print('Connected by', addr)

        filename = conn.recv(BUFFER_SIZE).decode('utf-8')
            
        with open(filename, "wb") as f:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    #analyse
                    
                    print("analysing..")
                    break

                f.write(data)
                print("writing...")
                
        

        print("finished")
        
        
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    while True:
        try:
            s.connect((HOST, PORT))
            break
        except:
            pass

    
    s.send(analyser.analyse(filename).encode())

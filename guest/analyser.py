import time
import subprocess, os


def procmon():
    os.system("C:\\Users\IEUser\Downloads\ProcessMonitor\ProcMon.exe -accepteula /backingfile C:\\Users\IEUser\Desktop\log.pml /quiet")
    time.sleep(5)
    os.system("C:\\Users\IEUser\Downloads\ProcessMonitor\ProcMon.exe /terminate")

def run(filename):
    subprocess.run(["C:\\Users\IEUser\Desktop\\" + filename])
    tasklist = subprocess.check_output(["tasklist", "/FO", "csv"])
    tasklist = tasklist.decode().split('\n')
    for item in tasklist:
        item = item.replace("\"", "")
        item = item.split(',')
        if item[0] == "cmd.exe":
            print(item[1])
            return item[1]


def pesieve(pid):
    os.system("C:\\Users\IEUser\Downloads\pe-sieve64.exe /pid " + pid + " /quiet /json > pe-sieve.json")
    
def analyse(filename):
    #procmon()
    pid = run(filename)
    pesieve(pid)
    return filename

if __name__ == "__main__":
    analyse("helloworld.exe")

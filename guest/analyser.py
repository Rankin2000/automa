import time
import subprocess, os

#Runs procmon, not used
def procmon():
    os.system("C:\\Users\IEUser\Downloads\ProcessMonitor\ProcMon.exe -accepteula /backingfile C:\\Users\IEUser\Desktop\log.pml /quiet")
    time.sleep(5)
    os.system("C:\\Users\IEUser\Downloads\ProcessMonitor\ProcMon.exe /terminate")

#Runs file and returns pid
def run(filename):
    process = subprocess.Popen("C:\\Users\IEUser\Desktop\\" + filename)
    return process.pid

#Runs pesieve on pid
def pesieve(pid):
    os.system("C:\\USers\IEUser\Downloads\pe-sieve64.exe /pid " + str(pid) + " /quiet /json > pe-sieve.json")

#Run sample and pesieve then return pid
def analyse(filename):
    pid = run(filename)
    print(pid)
    pesieve(pid)
    return 

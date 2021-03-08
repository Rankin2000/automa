import time
import subprocess, os

def procmon():
    os.system("C:\\Users\IEUser\Downloads\ProcessMonitor\ProcMon.exe -accepteula /backingfile C:\\Users\IEUser\Desktop\log.pml /quiet")
    time.sleep(5)
    os.system("C:\\Users\IEUser\Downloads\ProcessMonitor\ProcMon.exe /terminate")

def run(filename):
    subprocess.run(["C:\\Users\IEUser\Desktop\\" + filename])

def analyse(filename):
    run(filename)
    procmon()
    return filename

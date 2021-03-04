import time
import os
def procmon():
    os.system("C:\\Users\IEUser\Downloads\ProcessMonitor\ProcMon.exe -accepteula /backingfile C:\\Users\IEUser\Desktop\log.pml /quiet")
    time.sleep(5)
    os.system("C:\\Users\IEUser\Downloads\ProcessMonitor\ProcMon.exe /terminate")

def analyse(filename):
    procmon()
    return filename


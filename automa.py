#Filesize needs added
#fix --output for multiple files
#Only displays imphash


import argparse
import os, subprocess
import hashlib
import pefile
import vt
import json
import time
import sockets, volatility, formatter
import threading

#VirusTotal API Key
api = "71f11256d158446b715bc3410886630f782ae6a10e151e2fb048b84f287b307d"

#Flags
parser = argparse.ArgumentParser()
parser.add_argument("sample", help="Malware sample to be analysed", nargs='+')
parser.add_argument("-o", "--output", type=argparse.FileType("w"), help="Specifies output file for results to be saved to. Defaults to output.html")
args = parser.parse_args()


class Sample:
    def __init__(self, name):
        self.name = name
        self.md5 = str(subprocess.check_output("md5sum " + name, shell=True))[2:34]
        self.size = os.path.getsize(name) 
        self.malware = False

        self.reasons = {}

def strings(sample):
    print("Finding strings in sample using FLOSS...")
    os.system("floss -q --output-json floss.json " + sample.name + " > /dev/null" )

    with open("floss.json") as f:
        sample.floss = json.load(f)
    
def peFile(sample):
    print("Enumaration using PEFile...")
    pe = pefile.PE(sample.name)
    #help(pefile.PE)    
    if pe.is_exe():
        sample.filetype = "exe"
    elif pe.is_dll():
        sample.filetype = "dll"


    sample.pewarnings =  pe.get_warnings()
    sample.imphash = pe.get_imphash()
    sample.peinfo = pe.dump_info()

def capa(sample):
    print("Finding the capabilities of the sample using capa")
    os.system("./capa -j " + sample.name + " > samplecapa")


    with open("samplecapa") as f:
        sample.capa = json.load(f)

def virustotal(sample):
    print("Uploading to VirusTotal...")
    try:
        client = vt.Client(api)
        try:
            file = client.get_object("/files/" + sample.md5)
        except:
            with open(sample.name, "rb") as f:
                analysis = client.scan_file(f, wait_for_completion=True)
                
            file = client.get_object("/files/" + sample.md5)

        client.close()
        sample.results = {}
    
        for key in file.last_analysis_results:
            sample.results[key] = file.last_analysis_results[key]
            

    except vt.client.aiohttp.ClientConnectorError:
        client.close()
        pass

    
def unpacker(sample):
    print("Unpacking sample...")
    os.system("unipacker " + sample.name)
    
    print("Finding capabilites using capa on unpacked sample...")
    os.system("./capa -j unpacked_" + sample.name + " > samplecapa")


    with open("samplecapa") as f:
        sample.capaunpacked = json.load(f)

def dynamicanalysis(sample): 
    print("Using volatility to analyse memory dump from VM...")
    sample.ramscan = volatility.plugin("ramscan")
    sample.cmdcheck = volatility.plugin("cmdcheck")
    
    #Ramscan
    evidence = []
    if sample.ramscan:
        for item in sample.ramscan["rows"]:

#            if item[1] == sample.pid and item[-1]:
#                evidence.append("The sample\'s PID " + sample.pid + " was found to have " + item[-1])
            if item[-1]:

                evidence.append("The process " + item[0] + " was also found to have " + item[-1])

        if evidence:
            sample.reasons["Volatility RAMScan"] = evidence


    #evidence = []
    #CMDCheck
    #if sample.cmdcheck:
    #    for item in sample.cmdcheck["rows"]:
    #        evidence.append("CMD Check found

    #PE-Sieve
    evidence = []
    if sample.pesieve:
        for item in sample.pesieve["scanned"]["modified"]:
            if item != "total":
                if sample.pesieve["scanned"]["modified"][item]:
                    evidence.append("Found " + str(sample.pesieve["scanned"]["modified"][item]) + " modules that were " + item)
                        
        if evidence:
            sample.reasons["PE-Sieve"] = evidence


def analysis(sample):
    
    malicious = []
    try:
        for key in sample.virustotal:
            if sample.virustotal[key]["category"] == "malicious":
                malicious.append(key)
            #elif results[key] == "undetected":   
        if malicious:
            sample.malware = True
            sample.reasons["VirusTotal"] = malicious
    except AttributeError:
        pass

    try:
        if sample.pewarnings:
            sample.malware = True
            sample.reasons["pefile"] = sample.pewarnings
    except AttributeError:
        pass

    try:
        f = open("wordlist.txt", "r")
        wordlist = f.read().splitlines()
        f.close()
        suspicious = set()
        
        for key in sample.floss["strings"]:
            for string in sample.floss["strings"][key]:
                for word in wordlist:
                    if word in string.lower():
                        suspicious.add(string)
        if suspicious:
            sample.malware = True
            sample.reasons["FLOSS"] = suspicious
    except AttributeError:
        pass

    try:
        suspicious = []
        packed = False
        for key in sample.capa["rules"]:
            #If att&ck key in dictionary for that rule it should be more serious than just basic functionality and so therefore add to show in report
            if "att&ck" in sample.capa["rules"][key]["meta"]:
                suspicious.append(key)
                if "packed" in key:
                    packed = True

        if packed:
            unpacker(sample)

        if suspicious:        
            sample.malware = True
            sample.reasons["CAPA"] = suspicious
    except AttributeError:
        pass

    try:    
        if sample.capaunpacked:
            suspicious = []
            for key in sample.capaunpacked["rules"]:
                if "att&ck" in sample.capaunpacked["rules"][key]["meta"]:
                    suspicious.append(key)
            if suspicious:
                sample.malware = True
                sample.reasons["CAPAUnpacked"] = suspicious
    except AttributeError:
        pass

    
def runsample(sample):
    print("Sending sample to VM to run...")
    if subprocess.check_output(["vboxmanage", "list", "runningvms"]):
        running = True
    else:
        running = False



    #If vm running 
    if running:

        #Start INETSIM
        proc = subprocess.Popen(['sudo', 'inetsim', '--report-dir', '/home/debian/Desktop/honours/inetsim/'])
        sample.inetsimpid = proc.pid + 1
        #Send 
        while not sockets.send(sample.name):
            time.sleep(1)
            pass

        sample.pesieve = json.loads(sockets.receive())
        #print(sockets.receive())



        #Sleep to allow for sample to run    
        time.sleep(10)
        os.system("sudo kill " + str(sample.inetsimpid))


        dynamicanalysis(sample)
 
#Creates list based on files passed
samples = []
for file in args.sample:
    samples.append(Sample(file)) 

#Scan each file that was passed
for sample in samples:

#    os.system("VBoxManage snapshot vm restore automa")
#    os.system("VBoxManage startvm vm")

#    time.sleep(5)
    #Send sample to server and get pid in return
#    thread = threading.Thread(target=runsample, args=(sample,))
#    thread.start()



    strings(sample)
    peFile(sample)
    capa(sample)
    virustotal(sample)

 #   thread.join()

    analysis(sample)
    print("Analysis Complete.\nReport being created...")
    if args.output:
        output_file = args.output
    else:
        output_file = open(sample.name + "output.html", "w") 

    output_file.write(formatter.html(sample))
  
    output_file.close()
    print("Report Finished")
    print("Resetting VM")
    os.system("VBoxManage controlvm vm poweroff")

    time.sleep(3)


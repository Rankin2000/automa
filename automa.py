import argparse
import os, subprocess
import pefile
import vt
import json
import time
import sockets, volatility, formatter
import threading

#VirusTotal API Key
api = "replace with your api key"


#Command Line Arguments
parser = argparse.ArgumentParser()
parser.add_argument("sample", help="Malware sample to be analysed", nargs='+')
args = parser.parse_args()

#Class for samples to allow multiple submissions
class Sample:
    #Initalise variables
    def __init__(self, name):
        self.name = name
        #Gets MD5 Hash of sample
        self.md5 = str(subprocess.check_output("md5sum " + name, shell=True))[2:34]
        self.size = os.path.getsize(name) 

        #If tool finds anything suspicious
        self.suspicious = False
        #All items found suspicious
        self.reasons = {}

#Runs FLOSS on sample
def strings(sample):
    print("Finding strings in sample using FLOSS...")
    #Runs floss which outputs json to the file floss.json
    os.system("./floss -q --output-json floss.json " + sample.name + " > /dev/null" )

    #Saves the data from floss.json to the sample object's variable floss
    with open("floss.json") as f:
        sample.floss = json.load(f)

#Runs all PEFile functionality
def peFile(sample):
    print("Enumaration using PEFile...")
    #Creates pefile pe object from sample
    pe = pefile.PE(sample.name)

    #Detects if file is exe or dll, implemented for future work to allow for DLLs to be analysed
    if pe.is_exe():
        sample.filetype = "exe"
    elif pe.is_dll():
        sample.filetype = "dll"

    #Gets warnings of pe from pefile
    sample.pewarnings =  pe.get_warnings()
    #Gets the import hash
    sample.imphash = pe.get_imphash()
    #Gets complete dump of info
    sample.peinfo = pe.dump_info()

#Runs capa
def capa(sample):
    #Saves capa's json output to capa.json 
    print("Finding the capabilities of the sample using capa")
    os.system("./capa -j " + sample.name + " > capa.json")

    #Saves json to capa variable of sample object
    with open("capa.json") as f:
        sample.capa = json.load(f)

#VirusTotal API functionality
def virustotal(sample):
    print("Uploading to VirusTotal...")
    try:
        #Create API client
        client = vt.Client(api)

        #Attempt to get file from VirusTotal
        try:
            file = client.get_object("/files/" + sample.md5)
        #If can't find upload
        except:
            #Upload
            with open(sample.name, "rb") as f:
                analysis = client.scan_file(f, wait_for_completion=True)
            #Get file once uploaded
            file = client.get_object("/files/" + sample.md5)

        #Close client
        client.close()

        #Saves the results to virustotal variable
        sample.virustotal = {}
        for key in file.last_analysis_results:
            sample.virustotal[key] = file.last_analysis_results[key]
            
    #If error connector error close client
    except vt.client.aiohttp.ClientConnectorError:
        client.close()

#Uses unipacker to attempt to unpack the sample
def unpacker(sample):
    print("Unpacking sample...")
    #Runs unipacker on sample
    os.system("unipacker " + sample.name)
    
    #Run capa on the new unpacked sample
    print("Finding capabilites using capa on unpacked sample...")
    os.system("./capa -j unpacked_" + sample.name + " > capa.json")

    #Saves json to capa unpacked variable of sample object
    with open("capa.json") as f:
        sample.capaunpacked = json.load(f)

#Runs all dynamic analysis
def dynamicanalysis(sample): 
    print("Using volatility to analyse memory dump from VM...")
    #Gets dump from VM
    volatility.getdump()

    #Runs ramscan volatility plugin on VM dump
    sample.ramscan = volatility.plugin("ramscan")
    #Runs cmdcheck volatility plugin on VM dump
    sample.cmdcheck = volatility.plugin("cmdcheck")
    
    #Check if RAMSCAN found any suspicious items and add to sample's reasons variable
    evidence = []
    try:
        if sample.ramscan:
            for item in sample.ramscan["rows"]:
                if item[-1]:
                    evidence.append("The process " + item[0] + " was also found to have " + item[-1])
            if evidence:
                sample.reasons["Volatility RAMScan"] = evidence
    except:
        pass

    #Check if PE-Sieve found any suspicious items and add to sample's reasons variable
    evidence = []
    try:
        if sample.pesieve:
            for item in sample.pesieve["scanned"]["modified"]:
                if item != "total" and item != "unreachable_file":
                    if sample.pesieve["scanned"]["modified"][item]:
                        evidence.append("Found " + str(sample.pesieve["scanned"]["modified"][item]) + " modules that were " + item)    
            if evidence:
                sample.reasons["PE-Sieve"] = evidence
    except:
        pass

#Checks all static items for suspicious items
def analysis(sample):
    #Check VirusTotal result for malicious items
    malicious = []
    try:
        for key in sample.virustotal:
            if sample.virustotal[key]["category"] == "malicious":
                malicious.append(key)
        if malicious:
            sample.suspicious = True
            sample.reasons["VirusTotal"] = malicious
    except AttributeError:
        pass

    #If pewarnings exist
    try:
        if sample.pewarnings:
            sample.suspicious = True
            sample.reasons["pefile"] = sample.pewarnings
    except AttributeError:
        pass
    
    #Uses wordlist to try find any malicious strings in FLOSS results
    try:
        #Get words from wordlist
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
            sample.suspicious = True
            sample.reasons["FLOSS"] = suspicious
    except AttributeError:
        pass
    
    #If capa found any serious functionality
    try:
        suspicious = []
        packed = False
        for key in sample.capa["rules"]:
            #If att&ck key in dictionary for that rule it should be more serious than just basic functionality and so therefore add to show in report
            if "att&ck" in sample.capa["rules"][key]["meta"]:
                suspicious.append(key)
                if "packed" in key:
                    packed = True

        #If packed
        if packed:
            unpacker(sample)

        if suspicious:        
            sample.suspicious = True
            sample.reasons["CAPA"] = suspicious
    except AttributeError:
        pass

    #If capa found any serious functionality after unpacked
    try:    
        if sample.capaunpacked:
            suspicious = []
            for key in sample.capaunpacked["rules"]:
                if "att&ck" in sample.capaunpacked["rules"][key]["meta"]:
                    suspicious.append(key)
            if suspicious:
                sample.suspicious = True
                sample.reasons["CAPAUnpacked"] = suspicious
    except AttributeError:
        pass

#Run sample in VM
def runsample(sample):
    print("Sending sample to VM to run...")

    #Get running VMs
    if subprocess.check_output(["vboxmanage", "list", "runningvms"]):
        running = True
    else:
        running = False

    #If VM running
    if running:
        #Start INETSIM
        proc = subprocess.Popen(['sudo', 'inetsim', '--report-dir', '/home/stuart/Desktop/honours/inetsim/'])
        
        #Get INetSim PID that will be used to shutdown process
        sample.inetsimpid = proc.pid + 1

        #Send sample to VM
        sockets.send(sample.name)
        try:
            #Try and get PESieve results
            sample.pesieve = json.loads(sockets.receive())
        except:
            pass


        #Sleep to allow for sample to run    
        time.sleep(20)

        #Run Dynamic Analysis
        dynamicanalysis(sample)
        #Kill INetSim Process
        os.system("sudo pkill inetsim")
        #Wait for INetSim to finish
        time.sleep(2)
 
#Creates list based on files passed
samples = []
for file in args.sample:
    samples.append(Sample(file)) 

#Scan each file that was passed
for sample in samples:

    #Restore VM to correct snapshot
    os.system("VBoxManage snapshot vm restore Automa")
    #Start VM in headless mode
    os.system("VBoxManage startvm vm --type headless")

    #Wait for bott
    time.sleep(5)

    #Creates thread to send sample to server and get pid in return
    thread = threading.Thread(target=runsample, args=(sample,))
    thread.start()


    #Pass sample to all tools
    strings(sample)
    peFile(sample)
    capa(sample)
    virustotal(sample)
    
    #Join thread back
    thread.join()

    #Perform Analysis to find suspicious items
    analysis(sample)


    print("Analysis Complete.\nReport being created...")
    #If report folder doesnt exist create
    if not os.path.exists("reports/"):
        os.mkdir("reports")

    #Create report file in reports
    output_file = open("reports/" + sample.name + "output.html", "w") 
    #Get HTML format of report and write to new file
    output_file.write(formatter.html(sample))
    #Close file
    output_file.close()

    #Finish
    print("Report Finished")
    print("Resetting VM")
    #Power off the VM
    os.system("VBoxManage controlvm vm poweroff")



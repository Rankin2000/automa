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
import sockets, volatility
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

def inetsimformat(pid):
    try:
        #INetSim report is made as root so needs permission changes
        os.system("sudo chmod 444 /home/debian/Desktop/honours/inetsim/report." + str(pid) + ".txt > /dev/null")

        output = "<h3>INetSim</h3>"
        with open("/home/debian/Desktop/honours/inetsim/report." + str(pid) + ".txt") as f:
            for line in f.readlines():
                output += "<pre>" + line + "</pre>"
        return output
    except:
        return ""
        
    
def format(sample):
    output = "<body style='font-family:Arial;'>"
    output += "<h1>" + sample.name + "</h1>\n"
    output +="<table><tr><th>Filename</th><td>" + sample.name + "</td></tr>"
    output += "<tr><th>MD5</th><td>" + sample.md5 + "</td></tr>"
    output += "<tr><th>ImpHash</th><td>" + sample.imphash + "</td></tr>"
    output += "</table>"

    if sample.malware:
        output += "<h5>Here are some items that Automa found to be suspicious:</h5>"
        output += "<table>"
        for reason in sample.reasons:
            output += "<tr><td>" + reason + "</td><td>"
            output += "<ul>"

            for evidence in sample.reasons[reason]:
                output += "<li>" + evidence + "</li>"
            output += "</ul></td></tr>"
        output += "</table>"
    else:
        output += "<p>Automa failed to find any suspicious items in the sample. However, refer to the results below for a better idea of the sample</p>"
    
    try:
        if sample.peinfo:
            output += "<h2>PEFile Dump</h2>"
            output += "<p>" + sample.peinfo.replace('\n', '<br>') + "</p>"
    except AttributeError:
        pass

    try:
        if sample.floss:
            output += "<h2>FLOSS Results</h2>"
            for key in sample.floss["strings"]:
                output += "<h4>" + key.replace("_", " ") + "</h4>"
                if key == "decoded_strings":
                    output += "<ul>"
                    for string in sample.floss["strings"][key]:
                        output += "<li>" + string + "</li>"
                    output += "</ul>"

                if sample.floss["strings"][key]:
                    output += "<ul>"
                    for string in sample.floss["strings"][key]:
                        #Replaces less than symbol with html entity as was causing bug that was creating unclosed comments
                        output += "<li>" + string.replace("<", "&lt") + "</li>"
                    output += "</ul>"
                else:
                    output += "<p>FLOSS found 0 " + key.replace("_", " ") + "</p>"

    except AttributeError:
        pass
    try:
        if sample.capa:
            output += "<h2>FireEye's Capa</h2>"
        if sample.capa["rules"]:
            output += "<p>Here are the capabilities capa found: </p>"
            output += "<ul>"
            for key in sample.capa["rules"]:
                output += "<li>" + key + "</li>"
            output += "</ul>"
                
        else:
            output += "<p>Capa found 0 capabilities in this sample. This could be because it is safe or the file successfully hid its functionality using tools like packers</p>"
        output += "<p>Manually run Capa on the sample if more detailed is required</p>"
    except AttributeError:
        pass

    try: 
        if sample.capaunpacked:
            output += "<h2>Unpacked with Unipacker and Capa</h2>"

        if sample.capaunpacked["rules"]:
           output += "<p>Here are the capabilities capa found on the attempted unpack: </p>"
           output += "<ul>"
           for key in sample.capaunpacked["rules"]:
               output+= "<li>" + key + "</li>"
           output += "</ul>"     
        else: 
            output += "<p>Capa found 0 capabilities in the unpacked version of the sample.</p>"
    except AttributeError:
        pass

    try:
        if sample.results:
            output += "<h2>VirusTotal Results</h2>"
            output += "<table>"
            for key in sample.results:
                output += "<tr>"
                if sample.results[key]["result"]:
                    output += "<th>" + key + "</th><td>" + sample.results[key]["category"] + "</td><td>" + sample.results[key]["result"] + "</td>"
                else:

                    output += "<th>" + key + "</th><td>" + sample.results[key]["category"] + "</td>"
                output += "</tr>"

            output += "</table>"
            output += "The detection rate is: " + str(len(sample.reasons["VirusTotal"])) + "/" + str(len(sample.results))
    except AttributeError:
        pass
    except KeyError:
        pass

    try:
        if sample.inetsimpid:
            output += inetsimformat(sample.inetsimpid)
    except AttributeError:
        pass

    try:
        if sample.pesieve:
            output += "<h2>PE-Sieve</h2>"
            output += "<p>PE-Sieve scanned a total of " + str(sample.pesieve["scanned"]["total"]) + " modules</p>"
            
            output += "<table>"
            for item in sample.pesieve["scanned"]["modified"]:
                output += "<tr><th>" + item.replace("_", " ") + "</th><td>" + str(sample.pesieve["scanned"]["modified"][item]) + "</td></tr>"
            output += "</table>"
             
    except AttributeError:
        pass

    try: 
        if sample.ramscan or sample.cmdcheck:
            output += "<h2>Volatility</h2>"
            if sample.ramscan:
                output += "<h3>Plugin: Ramscan</h3>"
                output += "<table><tr>"
                for column in sample.ramscan["columns"]:
                    output += "<th>" + column + "</th>"
                output += "</tr>"

                for row in sample.ramscan["rows"]:
                    output += "<tr>"
                    for item in row:
                        output += "<td>" + str(item) + "</td>"
                    output += "</tr>"
                output += "</table>"

            if sample.cmdcheck:
                output += "<h3>Plugin: CMDCheck</h3>"
                output += "<table><tr>"
                for column in sample.cmdcheck["columns"]:
                    output += "<th>" + column + "</th>"
                output += "</tr>"

                for row in sample.cmdcheck["rows"]:
                    output += "<tr>"
                    for item in row:
                        output += "<td>" + str(item) + "</td>"
                    output += "</tr>"
                output += "</table>"
    except AttributeError:
        pass
    
    return output

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
        for key in sample.results:
            if sample.results[key]["category"] == "malicious":
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

        #sample.pesieve = json.load(sockets.receive())
        print(sockets.receive())



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

    os.system("VBoxManage snapshot vm restore automa")
    os.system("VBoxManage startvm vm")

    time.sleep(5)
    #Send sample to server and get pid in return
    thread = threading.Thread(target=runsample, args=(sample,))
    thread.start()



    strings(sample)
    peFile(sample)
    capa(sample)
    virustotal(sample)

    thread.join()

    analysis(sample)
    print("Analysis Complete.\nReport being created...")
    if args.output:
        output_file = args.output
    else:
        output_file = open(sample.name + "output.html", "w") 
    output_file.write(format(sample))
  
    output_file.close()
    print("Report Finished")
    print("Resetting VM")
    os.system("VBoxManage controlvm vm poweroff")

    time.sleep(3)


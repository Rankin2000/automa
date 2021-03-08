#Filesize needs added
#fix --output for multiple files
#Only displays imphash


import argparse
import os, subprocess
import hashlib
import pefile
import vt
import json
import sockets, volatility

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
    os.system("floss -q --output-json floss.json " + sample.name + " > /dev/null" )

#    f = open("strings.txt", "r")
#    sample.strings = f.read().splitlines()
#    f.close()
    with open("floss.json") as f:
        sample.floss = json.load(f)
    
def peFile(sample):
    pe = pefile.PE(sample.name)
    #help(pefile.PE)    
    if pe.is_exe():
        print("File is exe")
    elif pe.is_dll():
        print("File is dll")


    sample.pewarnings =  pe.get_warnings()
    sample.imphash = pe.get_imphash()
    sample.peinfo = pe.dump_info()

def capa(sample):
    os.system("./capa -j " + sample.name + " > samplecapa")


    with open("samplecapa") as f:
        sample.capa = json.load(f)
 

   

        #print(sample.capa["rules"][key])
#    for key in sample.capa["rules"]:
#        for item in sample.capa["rules"][key]["meta"]["scope"]:
#            print(item)
#            scope = ""
#            for character in sample.capa["rules"][key]["meta"]["scope"]:
#                scope += character.replace("\n", "")
#
#            print(scope)
#        print("\n\n")

def virustotal(sample):
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

def format(sample):
    output = "<body style='font-family:Arial;'>"
    output += "<h1>" + sample.name + "</h1>\n"
    output +="<table><tr><th>Filename</th><td>" + sample.name + "</td></tr>"
    output += "<tr><th>MD5</th><td>" + sample.md5 + "</td></tr>"
    output += "<tr><th>ImpHash</th><td>" + sample.imphash + "</td></tr>"
    output += "</table>"

    if sample.malware:
        output += "<p>The sample is believed to be malicious based on Automa's analysis.</p>"
        output += "<h5>Reasons:</h5>"
        output += "<table>"
        for reason in sample.reasons:
            output += "<tr><td>" + reason + "</td><td>"
            output += "<ul>"

            for evidence in sample.reasons[reason]:
                output += "<li>" + evidence + "</li>"
            output += "</ul></td></tr>"
        output += "</table>"
    else:
        output += "<p>The sample cannot be determined to be malicious based on Automa's analysis. Refer to the results below for a better idea</p>"
    
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

    return output

def unpacker(sample):
    os.system("unipacker " + sample.name)
    
    os.system("./capa -j unpacked_" + sample.name + " > samplecapa")


    with open("samplecapa") as f:
        sample.capaunpacked = json.load(f)

def memoryanalysis(sample): 
    sample.ramscan = volatility.plugin("ramscan")
    sample.cmdcheck = volatility.plugin("cmdcheck")
    
    #Ramscan
    evidence = []
    if sample.ramscan:
        for item in sample.ramscan["rows"]:
            if item[1] == sample.pid and item[-1]:
                evidence.append("The sample\'s PID " + sample.pid + " was found to have " + item[-1])
            elif item[-1]:
                evidence.append("The process " + item[0] + " was also found to have " + item[-1])
        sample.reasons["Volatility RAMScan"] = evidence

    evidence = []
    #CMDCheck
    #if sample.cmdcheck:
    #    for item in sample.cmdcheck["rows"]:
    #        evidence.append("CMD Check found


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

    
 
#Creates list based on files passed
samples = []
for file in args.sample:
    samples.append(Sample(file)) 

#Scan each file that was passed
for sample in samples:
    strings(sample)
    peFile(sample)
    capa(sample)
    virustotal(sample)


#    print("\n\n\n" + str(str(sample.size).encode())+ "\n\n")
    sockets.send(sample.name)
    sample.pid = sockets.receive()
    volatility.getdump()
    memoryanalysis(sample)

    print("PID = " + sample.pid)

    #volatility.run()
    #saveOutput() 

    #print(sockets.receive())
    analysis(sample)

    if args.output:
        output_file = args.output
    else:
        output_file = open(sample.name + "output.html", "w") 

    output_file.write(format(sample))
  
    output_file.close()





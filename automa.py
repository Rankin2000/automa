#Filesize needs added

import argparse
import os, subprocess
import hashlib
import pefile
import vt

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

    malware = False

    def strings(self):
        os.system("python2.7 flosspractice.py " + self.name + " > strings.txt")

        f = open("strings.txt", "r")
        sampleStrings = f.read().splitlines()
        f.close()
        
        f = open("wordlist.txt", "r")
        wordlist = f.read().splitlines()
        f.close()
        
        #print(sampleStrings)
        self.suspiciousStrings = []
        for string in sampleStrings:
            if string != "":
                if string.lower() in wordlist:
                    self.suspiciousStrings.append(string)

        #print(self.suspiciousStrings)

    
    def peFile(self):
        pe = pefile.PE(args.sample)
#    help(pefile.PE)    
        if pe.is_exe():
            print("File is exe")
        elif pe.is_dll():
            print("File is dll")

        pe.print_info()
    def capa(self):
        os.system("./capa " + args.sample + " > capa.txt")

    def virustotal(self):
        client = vt.Client(api)
        try:
            file = client.get_object("/files/" + self.md5)
        except:
            with open(self.name, "rb") as f:
                analysis = client.scan_file(self.name, wait_for_completion=True)
            file = client.get_object("/files/" + self.md5)

        client.close()
        self.results = {}
        self.malicious = []
        self.undetected = []
        for key in file.last_analysis_results:
            self.results[key] = file.last_analysis_results[key]["category"]
            if self.results[key] == "malicious":
                self.malicious.append(key)
            elif self.results[key] == "undetected":
                self.undetected.append(key)
        
    def format(self):
        output = ""
        output += "<h1>" + self.name + "</h1>\n"
        output +="<table><tr><th>Filename</th><td>" + self.name + "</td></tr>"
        output += "<tr><th>MD5</th><td>" + self.md5 + "</td></tr>"
        output += "</table>"

        if self.malware:
            output += "<p>The sample is believed to be malicious</p>"
            output += "<h5>Reasons:</h5>"
            output += "<table>"
            for reason in self.reasons:
                output += "<tr><td>" + reason + "</td><td>"
                output += "<ul>"

                for evidence in self.reasons[reason]:
                    output += "<li>" + evidence + "</li>"
                output += "</ul></td></tr>"
            output += "</table>"
            
        output += "<h2>VirusTotal Results</h2>"
        output += "<table>"
        for key in self.results:
            output += "<tr><th>" + key + "</th><td>" + self.results[key] + "</td></tr>"

        output += "</table>"
        output += "The detection rate is: " + str(len(self.malicious)) + "/" + str(len(self.undetected) + len(self.malicious))
        return output

    def analysis(self):
        self.reasons = {}

        if self.malicious:
            self.malware = True
            self.reasons["VirusTotal"] = self.malicious
        if self.suspiciousStrings:
            self.malware = True
            self.reasons["FLOSS"] = self.suspiciousStrings
 
#Creates list based on files passed
samples = []
for file in args.sample:
    samples.append(Sample(file)) 

#Scan each file that was passed
for sample in samples:
    sample.strings()
    #peFile()
    #capa()
    sample.virustotal()
    #saveOutput() 

    sample.analysis()

    if args.output:
        output_file = args.output
    else:
        output_file = open(sample.name + "output.html", "w") 

    output_file.write(sample.format())
  
    output_file.close()





import argparse
import os, subprocess
import hashlib
import pefile
import vt

#VirusTotal API Key
api = "71f11256d158446b715bc3410886630f782ae6a10e151e2fb048b84f287b307d"

#Flags
parser = argparse.ArgumentParser()
parser.add_argument("sample", help="Malware sample to be analysed")
parser.add_argument("-o", "--output", type=argparse.FileType("w"), help="Specifies output file for results to be saved to. Defaults to output.html")
args = parser.parse_args()


malicious = False

def strings():
    os.system("python2.7 flosspractice.py " + args.sample + " > strings.txt")
    f = open("strings.txt", "r")
    sampleStrings = f.read().splitlines()
    f.close()
    f = open("wordlist.txt", "r")
    wordlist = f.read().splitlines()
    f.close()
    print(sampleStrings)
    suspiciousStrings = []
    for string in sampleStrings:
        if string != "":
            if string.lower() in wordlist:
                suspiciousStrings.append(string)

    print(suspiciousStrings)

def saveResult(output):
    if args.output:
        output_file = args.output
    
    else:
        output_file = open("output.html", "w") 

    output_file.write("Filename: " + filename)
    output_file.write("MD5: " + md5)
    

    output_file.write("VirusTotal Results")
    for key in results:
        output_file.write(key + ": " + results[key]["category"])

    output_file.close()


def peFile():
    pe = pefile.PE(args.sample)
#    help(pefile.PE)    
    if pe.is_exe():
        print("File is exe")
    elif pe.is_dll():
        print("File is dll")

    pe.print_info()
def capa():
    os.system("./capa " + args.sample + " > capa.txt")

def virustotal():
    client = vt.Client(api)
    try:
        file = client.get_object("/files/" + md5)
    except:
        with open(filename, "rb") as f:
            analysis = client.scan_file(args.sample, wait_for_completion=True)
        file = client.get_object("/files/" + md5)

    client.close()
    results = {}
    malicious = []
    undetected = []
    for key in file.last_analysis_results:
        results[key] = file.last_analysis_results[key]["category"]
        if results[key] == "malicious":
            malicious.append(key)
        elif results[key] == "undetected":
            undetected.append(key)
        
    return results, malicious, undetected
        
def format():
    output = ""
    output += "<h1>" + filename + "</h1>\n"
    output +="<table><tr><th>Filename</th><td>" + filename + "</td></tr>"
    output += "<tr><th>MD5</th><td>" + md5 + "</td></tr>"
    output += "</table>"

    output += "<h2>VirusTotal Results</h2>"
    output += "<table>"
    for key in results:
        output += "<tr><th>" + key + "</th><td>" + results[key] + "</td></tr>"

    output += "</table>"
    return output

def analysis():
    
    #Strings
    #VirusTotal
    
    
    #if:
    #    return true
    #elif:
    #    return false

filename = os.path.basename(args.sample)

#filesize = 0
md5 = str(subprocess.check_output("md5sum " + filename, shell=True))[2:-3]
md5 = md5[0:-(len(filename))].strip()

strings()
#peFile()
capa()
results, malicious, undetected  = virustotal()
#saveOutput() 


if args.output:
    output_file = args.output
else:
    output_file = open("output.html", "w") 

output_file.write(format())
  
output_file.write("The detection rate is: " + str(len(malicious)) + "/" + str(len(undetected) + len(malicious)))
output_file.close()





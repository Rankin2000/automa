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
    os.system("python2.7 flosspractice.py " + args.sample + " >> strings.txt")
    f = open("strings.txt", "r")
    print(f.read())

def saveResult():
    if args.output:
        output_file = args.output
    
    else:
        output_file = open("output.html", "w") 
    
    output_file.write("test\n")
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
    os.system("./capa " + args.sample + " >> capa.txt")

def virustotal():
    client = vt.Client(api)
    try:
        file = client.get_object("/files/" + md5)
    except:
        with open(filename, "rb") as f:
            analysis = client.scan_file(args.sample, wait_for_completion=True)
        file = client.get_object("/files/" + md5)

    results = file.last_analysis_results
    client.close()

    print("VirusTotal Results")
    for key in results:
        print(key + ": " + results[key]["category"])
    
filename = os.path.basename(args.sample)

#filesize = 0
md5 = str(subprocess.check_output("md5sum " + filename, shell=True))[2:-3]
md5 = md5[0:-(len(filename))].strip()
print(filename)
print(md5)



strings()
peFile()
capa()
virustotal()
saveResult()
 

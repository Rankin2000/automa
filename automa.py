import argparse
import os
import pefile

#Flags
parser = argparse.ArgumentParser()
parser.add_argument("sample", help="Malware sample to be analysed")
parser.add_argument("-o", "--output", type=argparse.FileType("w"), help="Specifies output file for results to be saved to. Defaults to output.html")
args = parser.parse_args()


def strings():
#    sampleStrings = os.system("strings " + args.sample)
    print("test")

#    try:
#    vw = vivisect.VivWorkspace()
#        vw.loadFromFile
#        decodedStrings = floss.main.decode_strings(

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




strings()
peFile()
saveResult()
 

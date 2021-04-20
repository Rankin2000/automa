import os
import json

def getdump():
    #Remove previous memory dump as it doesn't like overwriting
    os.system("rm dump.elf")
    #Get new memory dump
    os.system("VBoxManage debugvm 'vm' dumpvmcore --filename=dump.elf")

def plugin(plugin):
    #Remove previous json files as plugin doesn't like overwriting
    os.system("rm /home/stuart/Desktop/honours/volatility/" + plugin + ".json")
    #Run plugin
#    os.system("/home/stuart/Desktop/honours/volatility2.6_standalone --plugins='/home/stuart/volatility-plugins/" + plugin + "' --profile='Win7SP1x64' -f /home/stuart/Desktop/honours/dump.elf " + plugin + " --output=json --output-file=/home/stuart/Desktop/honours/volatility/" + plugin + ".json")
    os.system("volatility --plugins='/home/stuart/Desktop/honours/volatility/' --profile='Win7SP1x64' -f /home/stuart/Desktop/honours/dump.elf " + plugin + " --output=json --output-file=/home/stuart/Desktop/honours/volatility/" + plugin + ".json")



    if os.path.isfile("/home/stuart/Desktop/honours/volatility/" + plugin + ".json"):
        with open("/home/stuart/Desktop/honours/volatility/" + plugin + ".json") as volatility:
            data = json.load(volatility)
        return data 


def getrules(directory):
    dirlist = os.listdir(directory)
    files = []
    for item in dirlist:
        path = os.path.join(directory, item)
        if os.path.isdir(path):
            files = files + getrules(path)
        else:
            files.append(path)
    return files


def yarascan(rules):
    if os.path.isfile(rules):
        #Run as file
        #os.system("/home/stuart/Desktop/honours/volatility2.6_standalone --profile='Win7SP1x64' -f dump.elf yarascan -y " + rules)
        os.system("volatility --profile='Win7SP1x64' -f dump.elf yarascan -y " + rules)
    else:
        for item in getrules(rules):
            os.system("volatility --profile='Win7SP1x64' -f dump.elf yarascan -y " + item)

if __name__ == "__main__":

#    yarascan("/home/stuart/Desktop/honours/rules/rules/malware")
    #getdump()
    #pid = 2592
    #data = plugin("ramscan")
    #print(data["columns"])
    #for item in data["rows"]:
    #    if item[1] == pid:
    #        print("Sample is here" + item[0])

    #    elif item[-1]:
   #         print(item[0] + " has a " + item[-1])


    data = plugin("cmdcheck")
    print(data["columns"])
    for item in data["rows"]:
        print(item)

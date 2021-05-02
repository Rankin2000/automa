import os
import json

def getdump():
    #Remove previous memory dump as VBox doesn't like overwriting
    os.system("rm dump.elf")
    #Get new memory dump
    os.system("VBoxManage debugvm 'vm' dumpvmcore --filename=dump.elf")

def plugin(plugin):
    #Remove previous json files as plugin doesn't like overwriting
    os.system("rm /home/stuart/Desktop/honours/volatility/" + plugin + ".json")
    #Run plugin
    os.system("volatility --plugins='/home/stuart/Desktop/honours/volatility/' --profile='Win7SP1x64' -f /home/stuart/Desktop/honours/dump.elf " + plugin + " --output=json --output-file=/home/stuart/Desktop/honours/volatility/" + plugin + ".json")

    #If result json file exists parse to return
    if os.path.isfile("/home/stuart/Desktop/honours/volatility/" + plugin + ".json"):
        with open("/home/stuart/Desktop/honours/volatility/" + plugin + ".json") as volatility:
            data = json.load(volatility)
        return data 



import os
import json

def getdump():
    os.system("VBoxManage debugvm 'vm' dumpvmcore --filename=dump.elf")

def plugin(plugin):
    os.system("/home/debian/Desktop/honours/volatility2.6_standalone --plugins='/home/debian/volatility-plugins/" + plugin + "' --profile='Win7SP1x64' -f /home/debian/Desktop/honours/dump.elf " + plugin + " --output=json --output-file=/home/debian/Desktop/honours/volatility/" + plugin + ".json")

    with open("/home/debian/Desktop/honours/volatility/" + plugin + ".json") as volatility:
        data = json.load(volatility)

    return data 


def report():
    pass



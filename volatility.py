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



if __name__ == "__main__":

    getdump()
    pid = 2592
    data = plugin("ramscan")
    print(data["columns"])
    for item in data["rows"]:
        if item[1] == pid:
            print("Sample is here" + item[0])

        elif item[-1]:
            print(item[0] + " has a " + item[-1])


    data = plugin("cmdcheck")
    print(data["columns"])
    for item in data["rows"]:
        print(item)

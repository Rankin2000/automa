import os.path
import time

SharedDir = "C:Users\windowsacc\Samples"
print(SharedDir)
filepath = SharedDir + "\sample"

while True:
    while not os.path.exists(filepath):
        time.sleep(1)

    if os.path.isfile(filepath):
        #Do analysis
        pass
    else:
        raise ValueError("%s isn't a file!" % filepath)



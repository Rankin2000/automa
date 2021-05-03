# Honours

## Summary
This a tool that was developed for my 4th year Ethical Hacking Honours Project.
It attempts to perform automatic malware analysis similar to that of Cuckoo Sandbox.
It utilises the following tools:
* FLOSS
* CAPA
* PEFile
* VirusTotal API
* Unipacker
* VMWare
* Volatility
* PE-Sieve

It saves the results to an HTML file as well attempting to highlight any supsicious items found by the tools.

## Scope
The tool is quite limited in its scope, it was designed specifically for Portable Executable files and the Virtual Machine agent was only designed Windows 7. 

## Installation
The tool lacks a lot of useful functionality that needs to be implemented in future work for example, it currently uses hard coded directories.

### Requirements
* Python 3
* VirtualBox

### Setup

1. Clone repository
2. Download and Install Requirements
    1. Download FLOSS binary to automa's directory.
    2. Download CAPA binary to automa's directory.
    3. Install Volatility.
    4. Downlaod RAMSCAN and CMDCheck from https://github.com/TazWake/volatility-plugins to directory "volatility" within automa's directory. 
       *Note: Volatility.py utilises hard-coded directories which can be adapted to your setup.*
    6. Install VirusTotal API Python Library, vt-py.
       *Note: You will have to replace the api key in automa.py with your own*
    8. Install pefile Python library.
    9. Install unipacker.
    10. Install INetSim.
        1. Configure INetSim to listen to 192.168.56.1 or the Virtual Network Interface IP
3. Set up Windows 7 VM
    1. Install Python 3.
    2. Copy the files from the guest folder to the VM.
    *Note: These files also utilise hard-coded directories which may need to be adapted depending on your setup.*
    4. Configure VM Network to be Host-Only and use 192.168.56.1/24.  
    5. Set static IP of Windows 7 to 192.168.56.2 and default gateway and DNS to 192.168.56.1
    6. Run the sockets.py file and save a snapshot named "automa".

## Usage
The tool can be used using the command line. Copy the sample to the automa directory. 
The outputted report can be found in the reports directory.
```
python3 automa.py sample
```
*Note: Multiple samples can be submitted seperated by a space*


### Contact
Likely you will run into issues and if so free to contact me.

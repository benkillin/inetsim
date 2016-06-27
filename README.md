# inetsim.py
A python script to simulate an "internet" in a lab environment by having the machine running the script be the gateway for a private lab network.

# Status
Currently the script does not function as intended.

# Why?
This script was originally developed while I was at the USCC cyber quests cyber camp that I went to several years ago. It was developed after a lesson on scapy, the python packet crafting library. I wanted to do something non trivial with scapy and something "fancy" so I thought about a use case where you want to directly execute malware that you know will reach out to a remote server but you are running in an "air gapped" network and want to be able to control what is going on. Since you might not be able to completely evaluate the malwares behavior unless it can contact a command and control server, I envisioned a server that would respond on all IP addresses and had various modules for simulating the endpoint server. 

This is pretty much the same thing as a Perl script that goes by the same name, inetsim.pl, but I wanted to develop this without re-writing the TCP/IP stack in python, so I wanted to utilize the built in stack of the Linux server you are running this script on. 

# License
GNU GENERAL PUBLIC LICENSE Version 3


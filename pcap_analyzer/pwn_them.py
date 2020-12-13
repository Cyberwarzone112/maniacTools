##Pcap research tool
#this tool uses tshark from wireshark, so make sure it is installed
#via cyberwarzone.com
import subprocess

tshark_location = r"C:/Program Files/Wireshark/tshark.exe"
pcap_location = r""

optionsx = {"1":'-r "' + pcap_location + '" --export-objects "http,destdir"'}


def get_objectsfrompcap():
    a = optionsx["1"] 
    subprocess.run([tshark_location, a])


get_objectsfrompcap()

import urllib2
import json
import time
import sys
import logging
import socket
import hashlib

# Third library
from optparse import OptionParser
from OTXv2 import OTXv2
import IndicatorTypes
from scapy.all import *
import shutil
import dpkt
import scapy


file_name  = "dump.pcap" # input pcap file
output_dir = "output/"   # output directory
PcapSplitter_path = "./PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter" # PcapSplitter path

url = 'http://ip.taobao.com/service/getIpInfo.php?ip='
API_KEY = 'f12f1aa045dadd4a269fc9bd74e2a5dd7f2b02eb8fa2111e86d6f7d75dbddc11'  #change your API_Key
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)

def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results

def Check_Ip_malicious(otx, ip):
    alerts = []
    try:
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
    # if can't analyze ip address
    except:
    	return False    
    
    pulses = getValue(result, ['pulse_info', 'pulses'])    
    if pulses:
        for pulse in pulses:
            if 'name' in pulse:            	
                alerts.append('In pulse: ' + pulse['name'])
    
    if len(alerts) > 0:
        return True
    else:
        return False
        
def check_pcap_malicious(pcap):
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECE = 0x40
	CWR = 0x80
	
	# check is tcp or udp
	pkt_1 = pcap[0]
	if (TCP not in pkt_1) and (UDP not in pkt_1):
		return False
    		
	# check not dns
	dst_ip = pkt_1[IP].dst
	src_ip = pkt_1[IP].src
	if dst_ip == "8.8.8.8" or src_ip == "8.8.8.8":
		return False
	
	# check with hand shake in tcp
	if TCP in pkt_1:
		if len(pcap) < 4:
			return False
		else:			
			pkt_1_flag = pcap[0]['TCP'].flags			
			pkt_2_flag = pcap[1]['TCP'].flags				
			pkt_3_flag = pcap[2]['TCP'].flags	
			
			if (pkt_1_flag & SYN) == False:
				return False
			if (pkt_2_flag & SYN and pkt_2_flag & ACK) == False:
				return False
			if (pkt_3_flag & ACK) == False:
				return False	
		
	return Check_Ip_malicious(otx, dst_ip)
	

def main():
	if os.path.isdir(output_dir) == False:
		os.mkdir(output_dir)
	
	cmd = PcapSplitter_path + ' -f ' + file_name + " -m connection -o " + output_dir
	os.system(cmd)
	
	split_filenames = os.listdir(output_dir)
	
	for split_filename in split_filenames:
		full_filename = output_dir + split_filename
		pcap = rdpcap(full_filename)
		is_malisious = check_pcap_malicious(pcap)		
		if is_malisious == False:
			cmd = "rm " + output_dir + split_filename
			os.system(cmd)
		
if __name__ == '__main__':
	main()

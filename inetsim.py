#!/usr/bin/python
#########################
# inetsim.py - stuff stuff stuff descriptions
#
# This thing doesn't work yet.
#
# @created 27 June 2013
# @date 11 June 2016
# @author benkillin
#
# Copyright (C) 2016 benkillin. All Rights Reserved.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#########################
# Be sure to fix scapy with this:
# http://hg.secdev.org/scapy/rev/7621f33286b9
#     1.1 --- a/scapy/supersocket.py	Mon Aug 27 11:56:19 2012 +0200
#     1.2 +++ b/scapy/supersocket.py	Mon Aug 27 11:56:31 2012 +0200
#     1.3 @@ -10,7 +10,7 @@
#     1.4  import socket,time
#     1.5  from config import conf
#     1.6  from data import *
#     1.7 -from scapy.error import warning
#     1.8 +from scapy.error import warning, log_runtime
#     1.9  
#    1.10  class _SuperSocket_metaclass(type):
#    1.11      def __repr__(self):

# http://books.google.com/books?id=WHcjc42p_MQC&pg=PA153&lpg=PA153&dq=scapy+L3Rawsocket&source=bl&ots=58yVnYmhvZ&sig=P_GDhSTDT8JSbJDIfqvfqJceBkY&hl=en&sa=X&ei=gq2wUvSpG6S-sQT9tYC4DA&ved=0CCgQ6AEwADgK#v=onepage&q&f=false
# super sockets
# to read and write packets to the network, scapy uses a super socket abstraction. a super socket is an object that provides operations to send and receive packets. it can rely on sockets or on libraries such as libpcap and libdnet. it manages BPF filtering and assembling and dissecting packets, so that you send and receive packet objects, not strings. Some super sockets offer layer 2 access to the network and others layer 3 access. the latter will manage the routing table lookup and chose a suitable layer 2 according to the output interface. both witll choose the layer class to instantiate when receiving a packet according to the interface link type.
# L2Socket and L3PacketSocket are the default for Linux. They use the PF_PACKET protocol family sockets. On other unixes, L2dnetSocket and L3dnetSocket are used. They rely on libpcap and libdnet to send and receive packets. The super-sockets to use are stored into conf.L2socket and conf.l3socket, so you could, for example, switch to use libpcap and libdnet even though you are on Linux. You could also write a new super-socket that could receive traffic remotely from a TCP tunnel. L2ListenSocket and l2pcapListenSocket are dumb super-sockets used only by sniff(). The one to use is stored in conf.L2listen. 
# Another layer 3 super socket exists. it uses SOCK_RAW type of PF_INET protocol family socket, also known as raw sockets. These kind of sockets are much more kernel assisted and work on most unixes. 
# BUT they are designed to help standard applications, not applications that try to send invalid traffic. 
# Among other limitations you will not be able to:
# 1) Send an IP packet to a network address present in your routing tables,
# 2) or and IP checksum set to zero because the kernel would compute it for you.
# If you try to have scapy interact with programs through your loopback interface, it would probably not work. You will see the packets with tcpdump but the target program will not. That is because the loopback interface does not work like a physical one. 
# If you want this to work, you have to send your packets through the kernel using PF_INET/SOCK_RAW sockets, i.e., by using L3RawSocket instead of L3PacketSocket or L3dnetSocket
# Super-sockets can be used directly to take advantage of the abstraction they provide that hides low-level details. You can either chose one directly or use those proposed by the conf object to also avoid chosing between native or libdnet/libpcap usage. Then, you can use send() and recv() methods to send and sniff. 
# If you want to write new applications that need to interact with the network and that cannot use sniff() and send() functions for performance or elegance reasons, super-sockets are the way to go. For example:
# >>> s=conf.L3socket(filter="icmp", iface="eth0")
# >>> while 1:
# ...   p=s.recv()
# ...   s.send(IP(dst="relay")/GRE()/p[IP])

from scapy.all import *

import os
import signal
import sys
import thread
import threading
from time import sleep
from subprocess import call

interfaceName = "eth0"
defaultGw = "0.0.0.0"

currentInterfaceNumber = 1

interfacesLock = threading.Lock()
processesLock = threading.Lock()
#packetLock = threading.Lock()
hashLock = threading.Lock()

interfaces = []
processes = []
pktHashes = []


####
#
def sigh(signal,frame):
	#kill all processes in global process list
	for proc in processes:
		try:
			proc.terminate()
		except:
			try:
				os.kill(proc.pid, signal.SIGINT)
			except:
				print("OH NO CANT KILL IT WITH FIRE!!! NOW ATTEMPTING TO KILL WITH 3000 FIRES!")
				call("kill -9 " + str(proc.pid), shell=True)
	
	#remove all interfaces in global interface list
	for int in interfaces:
		call("ifconfig " + int[0] + " down", shell=True)
	
	sys.exit(-1)

signal.signal(signal.SIGINT, sigh)

####
# TODO: this
def doTcpConn(pkt):
	print(pkt)
	destIP = pkt[0][IP].dst
	srcIP = pkt[0][IP].src
	destPort = pkt[0][TCP].dport
	
	#set up fake interface
	#ifconfig eth0:1 1.1.1.1 netmask 255.255.255.255
	newInterface = interfaceName + ":" + str(currentInterfaceNumber)
	
	# Ensure interface does not exist.
	addressListProc = subprocess.Popen("ifconfig -a | grep 'inet addr' | awk '{ print $2; }' | awk -F ':' '{ print $2; }'", shell=True, stdout=subprocess.PIPE)
	addressList = addressListProc.communicate()[0]

	if not (destIP in addressList):
		print(newInterface)
		# TODO: Test to see if setting the MAC this way works:
		# TODO: Verify the RandMAC() funciton returns a mac correctly formatted for this command
		# TODO: Find out if you can use native scapy stuff to add a new interface
		call("ifconfig " + newInterface + " " + destIP + " netmask 255.255.255.255 hw ether " + RandMAC(), shell=True)
		
		#add interface name to global interfaces list (using a lock)
		interfacesLock.acquire()
		interfaces.append((newInterface, destIP, ))
		interfacesLock.release()
	
	
	#ensure netcat for this dest IP is not already running:
	netcatList = subprocess.Popen("ps -ef | grep 'nc -s' | grep -v grep", shell=True, stdout=subprocess.PIPE).communicate()[0]
	
	if not (destIP in netcatList):
		#start netcat on fake interface with output redirected to file named by source IP
		proc = subprocess.Popen("/bin/nc -s " + destIP + " -l -p " + str(destPort) + " >> /tmp/" + srcIP + ".log", shell=True)
		
		#add netcat process info to gobal processes list (using a lock)
		processesLock.acquire()
		processes.append(proc)
		processesLock.release()
	
	#get interface name we need to send this packet to
	interface = subprocess.Popen("ifconfig -a | grep -B 2 " + destIP + " | grep 'Link encap' | awk '{ print $1; }'", shell=True, stdout=subprocess.PIPE).communicate()[0]
	# TODO: Use the already created newInterface variable??

	#TODO: make sure you get the other options for the IP and TCP layers that you forgot
	newPkt = IP(src=pkt[0][IP].src, dst=pkt[0][IP].dst)/TCP(flags=pkt[0][TCP].flags, sport=pkt[0][TCP].sport, dport=pkt[0][TCP].dport, seq=pkt[0][TCP].seq, ack=pkt[0][TCP].ack)/Raw(pkt[0][TCP].payload)
	
	# TODO: verify using the new socket works
	s=conf.L3socket(iface=interface)
	
	s.send(newPkt, iface=interface) #TODO: This doesn't work.
	

#####
# TODO: handle UDP services
def dispatch(pkt):	
	#all the packet lists should have only a single packet in them...
	if(pkt[0].haslayer(TCP) and pkt[0][TCP].flags == 0x02):
		#hash packet and compare to packet hash list
		infoStr = pkt[0][IP].src + ":" + str(pkt[0][TCP].sport) + "<->" + pkt[0][IP].dst + ":" + str(pkt[0][TCP].dport) + "@" + str(pkt[0][TCP].seq) + "&" + str(pkt[0][TCP].ack)
		h = hash(infoStr)
		
		if h in pktHashes:
			#remove hash from list
			print("already serviced the fuck out of this packet")
			sleep(1)
			hashLock.acquire()
			pktHashes.remove(h)
			hashLock.release()
		else:
			hashLock.acquire()
			pktHashes.append(h)
			hashLock.release()
			doTcpConn(pkt)
	else:
		print("ignored.")


		
conf.L3socket = L3RawSocket
#conf.L3socket = L3dnetSocket

# TODO: automatically add the rule to drop reset (RST) packets to iptables in the script. 
# Need the RST packets filtered out cuz by default the kernel will not know what to do with the packet before the fake interface has been created.

while True:
#	sniff(count=1,prn=lambda x: dispatch(x),lfilter=lambda x: x.haslayer(TCP),timeout=1)
	pkt = sniff(count=1,filter="tcp or udp")
	thread.start_new_thread(dispatch, (pkt, ))

	

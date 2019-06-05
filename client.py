

import sys,os
import subprocess
import socket
import threading
import time
import struct
import os.path
import urllib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import hashlib


alias="a"
criteria="a"
pings=1
s='Wrong parameters(Must be : client.py -e <end servers filename> -r <relay node filename>)\n'
lock = threading.Lock()
rtt=""
server = ""


relays = []

def Hash_string(strin):
	hashed = SHA256.new()
	hashed.update(str.encode(strin))
	
	return hashed.hexdigest()


def generate_keys():	#generating public-private key
	private_key = RSA.generate(1024)
	public_key = private_key.publickey()
	return (private_key.exportKey(format='PEM'),public_key.exportKey(format='PEM'))

def encrypt(message,key):
	encrypted = AES.new(str(key)[:32])
	tagged = (str(message) +(AES.block_size -len(str(message)) % AES.block_size) * "\0")
	cipher = base64.b64encode(encrypted.encrypt(tagged))
	print cipher
	return cipher

def decrypt_v(message,key):
    decrepted = AES.new(str(key)[:32])
    detagged = decrepted.decrypt(base64.b64decode(message))
    
    text = detagged.rstrip("\0")
    
    return text

def check_input(end_servers):	#checks input
	
	inpt = raw_input("Please give the alias of endserver,the number of pings to use and the criteria of routing :")
	
	while True:
		
		if inpt.count(" ")>2  or inpt.count(" ")<2:
			inpt = raw_input("Wrong syntax.Try again(Syntax: <alias name> <pings>(numeric) <criteria>(hopping||latency) :")
		else:
			alias,pings,criteria=inpt.split(" ")
			if pings.isdigit() and (criteria=="hops" or criteria=="latency"):
				if ", "+alias in open(end_servers).read() or alias+"," in open(relay_node).read():
					break
				else:
					inpt = raw_input("Alias not found.Try again (Syntax: <alias name> <pings>(numeric) <criteria>(hopping||latency) :")
					continue
			inpt = raw_input("Wrong syntax.Try again(Syntax: <alias name> <pings>(numeric) <criteria>(hopping||latency) :")
	return inpt

def relay_send(relay,port,data,amount_expected,filename):
	with lock:
		print "TRYING ",relay,"to port",port
		
		sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		ported = int(port)
		
		sock.connect((relay,ported))
		try:
			print "Succeed"
			message = data
			sock.sendall(message)
			
		
			data = sock.recv(1024)
			
			
			filename.write(str(data))
			filename.write("\n")
				
		finally:
			
			sock.close()

def relay_send_str(relay,port,data,amount_expected):
	
	print "TRYING ",relay,"to port",port
	
	sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ported = int(port)
	
	sock.connect((relay,ported))
	try:
		print "Succeed"
		message = data
		sock.sendall(message)
		
	
		data = sock.recv(amount_expected)
		return data
			
	finally:
		
		sock.close()
		
	
		

class CommunicateThread(threading.Thread): #handle connections
	def __init__(self,name,relay,port,data,expected,filename):
		threading.Thread.__init__(self)
		self.name = name
		self.port = port
		self.relay = relay
		self.data = data
		self.expected = expected
		self.filename = filename
	def run(self):
		if self.name is "relay_send":
			relay_send(self.relay,self.port,self.data,self.expected,self.filename)

class CustThread(threading.Thread): #handle of pings-traceroutes
	def __init__(self,name,server,pings,filename):
		threading.Thread.__init__(self)
		self.name =name
		self.server =server
		self.pings = pings
		self.filename = filename
	def run(self):
		if self.name is "ping":
			ping(self.server,self.pings,self.filename)
			
			
		if self.name is "traceroute":
			traceroute(self.server,self.filename)
			
		if self.name is "ping_l":
			ping_l(self.server,self.pings,self.filename)
		if self.name is "traceroute_l":
			traceroute_l(self.server,self.filename)

def traceroute(server,filename):
	with lock:
		ttl=1
		port=80
		pr = filename
		for ttl in range(1,30):
			sck=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			
			sck.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,int(ttl))
			sck.settimeout(1)
			try:
				sck.connect((server,port))
			except (socket.error , socket.timeout) as err:
				sck.close()
				continue
			print "TTL = ",ttl
			
			pr.write('server Hops = '+str(ttl))
			pr.close()
			
			break
def traceroute_l(server,filename):
	with lock:
		
		trc = os.system("traceroute -q 2 -w 3 -n "+server+" >> "+str(filename))
def ping(server,pings,filename):
	
	
		print(pings)
		pr = filename
		
		
		for x in range(0,int(pings)):
		
			
			
			proc = subprocess.Popen(['ping', '-c',"1",'-n',server],stdout=subprocess.PIPE)
				
			stdout, stderr = proc.communicate()
			
			if proc.returncode == 0:
				pr.write(stdout.decode('ASCII'))
			

				
			else:
				
				print 'Server is down'
				sys.exit("Exiting")
		pr.close()
			#ping.stdout.close()
def ping_l(server,pings,filename):
	
	
		
		pr = filename
			
			
		proc = subprocess.Popen(['ping', '-c', pings,'-n','-i','0.2','-W1',server],stdout=subprocess.PIPE)
			
		stdout, stderr = proc.communicate()
		
		if proc.returncode == 0:
			pr.write(stdout.decode('ASCII'))
		

			
		else:
			
			print 'Server is down'
			sys.exit("Exiting")
			#ping.stdout.close()
		pr.close()

def download_the_link(alias):
	with open("files/files2download.txt","rt") as in_file:
		for line in in_file:
			if alias in line:
				download_link = str(line)
				break
	if not download_link:
		sys.exit("Download link not found")
	
	testfile = urllib.URLopener()	#download file and store it with prefered extension

	testfile.retrieve(download_link, "file_downloaded."+str(download_link.split(".")[download_link.count(".")]))

def Main():
	if len(sys.argv)<5 or len(sys.argv)>5:
		
		print(s)
		sys.exit("Exiting")

	elif str(sys.argv[1])=="-e" and str(sys.argv[3])=="-r":
		end_servers=str(sys.argv[2])
		relay_node=str(sys.argv[4])
		if os.path.isfile(end_servers) and os.path.isfile(relay_node):
			
			alias,pings,criteria=check_input(end_servers).split(" ")
			private_key,public_key = generate_keys() #paragw ta private-public keyes
			
			data=[]
			with open(end_servers) as f:
				for line in f:
					if ", "+alias in line:
						data.append(line)
						break
			server,junk = str(data).split(",")
			server = server.replace("[","")
			server = server.replace("'","")
			ip = socket.gethostbyname(server)
			
			rr = open("relays_results.txt","w+") #dhmiourgei to file gia ta apotelesmata twn relays
			
			send_public_key = []
			message = public_key
			with open(relay_node) as in_file:#stelnw to public key tou client sta relays kai pairnw ta twn relays
				for line in in_file:
					relays.append(str(line.split(",")[0]))
					
					
					sended = relay_send_str(str(line.split(",")[1]),str(line.split(",")[2]),message,303)
					send_public_key.append(sended)

			for i in send_public_key:
				print i
			get_signatures=[]
			cout = 0
			with open(relay_node) as in_file: 
				for line in in_file:
					message = "OK" 
					ampla = relay_send_str(str(line.split(",")[1]),str(line.split(",")[2]),message,303)
					get_signatures.append(ampla)		
					
			 
			for i in get_signatures:	#tha eprepe na pernei tis upografes, na hasharei to text kai na kanei decrypt to cipher 
										#na tsekarei to cipher me to hashed an einai to idio kai na kanei verify
				print "Encrypted = ",i.encode()
				hashed = Hash_string("password")
				rashed = decrypt_v(i,private_key)
				print hashed
				print str(rashed)
				
			relays_initialized=[]		#dinei entolh sta relays na ksekinhsoun ping-traceroute
			with open(relay_node) as r:
				for line in r:
					
					data = str(pings)+" "+server
					relay_inited = CommunicateThread("relay_send",str(line.split(",")[1]),str(line.split(",")[2]),data,len("OK from ,"+str(line.split(",")[0])),rr)
					relays_initialized.append(relay_inited)
					relay_inited.start()
			

			pingD=open("ping_results.txt","w+")				#arxikopoihsh direct ping-traceroute
			trcD = open("direct_traceroute.txt","w+")
			ping_d = CustThread("ping",server,pings,pingD)
			traceroute_d = CustThread("traceroute",server,0,trcD)


			ping_d.start()
			traceroute_d.start()

			ping_d.join()
			rtt=0
			with open ('ping_results.txt', 'rt') as in_file:  
				for line in in_file: 
					if "rtt" in line:
						rtt = rtt+float(line.split("/")[4])


			direct_rtt=float(rtt)/int(pings)			#kratame to direct_ping se metablhth
			

			
			pingD.close()
			
			
			print "RTT_Direct = ",direct_rtt
			traceroute_d.join()
			trcD.close()
				
			
			
			relay_list_ping = []
			relay_list_traceroute = []
			count = 0
			with open (relay_node,'rt') as in_file:		#ksekinaw ta pings-traceroutes pros ta relays
				for line in in_file:
					
					
					
					
					ip = line.split(",")[1]
					
					pingx=open("ping_"+str(line.split(",")[0])+".txt","w+")
					pinged = CustThread("ping_l",ip,pings,pingx)
					relay_list_ping.append(pinged)
					
					traceroutex = open("traceroute_"+str(line.split(",")[0])+".txt","w+")
					tracerouted = CustThread("traceroute_l",ip,0,"traceroute_"+str(line.split(",")[0])+".txt")
					relay_list_traceroute.append(tracerouted)
					
					pinged.start()
					tracerouted.start()
					with lock:
						count=count+1
			
			
			for pinged in relay_list_ping:			
				pinged.join()
			


			for tracerouted in relay_list_traceroute:
				tracerouted.join()
			rtts = []
			
			with open (relay_node,'rt') as in_file:		#bgazw apotelesma
				for line in in_file:
					with open ('ping_'+str(line.split(",")[0])+'.txt', 'rt') as in_file:
						for l in in_file: 
							if "rtt" in l:
								rtt =float(l.split("/")[4])
								
								rtts.append(rtt)
								print "rtt in ping_"+str(line.split(",")[0])+" = ",rtt
				
			cout=0
			
			hopss = []
			with open (relay_node,'rt') as in_file:		#ksekinaw ta pings-traceroutes pros ta relays
				for line in in_file:
					with open ('traceroute_'+str(line.split(",")[0])+'.txt', 'rt') as in_file:  # Open file lorem.txt for reading of text data.
						i=0
						for l in in_file: # Store each line in a string variable "line"
							
							if "*" in l:
								i=i-1
								break
							i+=1
						print "hops in traceroute_"+str(line.split(",")[0])+" = ",i
						hopss.append(i)	
			cout=0
			
			
			
			
			#client-relay(response from relays)

			
			for ok in relays_initialized:
				ok.join()
			relays_results=[]		
			with open(relay_node) as r:
				for line in r:
					data = "OK Relay"
					length = len(str(line.split(",")[0])+","+","+"********")
					print(length)
					relay_res = CommunicateThread("relay_send",str(line.split(",")[1]),str(line.split(",")[2]),data,length,rr)
					relays_results.append(relay_res)
					relay_res.start()

			#wait
			for ok in relays_results:
				ok.join()		
			#files-decide whats is the best way
			min_rtt = direct_rtt
			rtt_best = "Direct"
			hops_best = "Direct"
			hops_are_not_same = True #metablhth gia na gnwrizoume an tha allaksoume to krhtirio epiloghs

			with open("direct_traceroute.txt","rt") as in_file:
				for line in in_file:
					min_hops = int(line.split(" ")[3])
					d_hops = min_hops

			with open("relays_results.txt","rt") as in_file:
				for line in in_file:
					rtt2 = float(line.split(",")[1])
					hops2 = int(line.split(",")[2])
					with open("ping_"+str(line.split(",")[0])+".txt","rt") as inp:
						for l in inp:
							if "rtt" in inp:
								rtt1=float(l.split("/")[4])
					with open("traceroute_"+str(line.split(",")[0])+".txt","rt") as inp:
						i=0
						for l in inp: 
							
							if "*" in l:
								i=i-1
								break
							i+=1
						hops1 = i
					if rtt1+rtt2<min_rtt:
						min_rtt=rtt1+rtt2
						rtt_best = str(line.split(",")[0])
					if hops1+hops2<min_hops:
						min_hops=hops1+hops2
						hops_best = str(line.split(",")[0])

			if min_hops == d_hops and criteria is "hops":
				hops_are_not_same=False
			if criteria is "hops" and hops_are_not_same is True:
				print "Best route is from "+hops_best
				download_from = hops_best
				if rtt_best=='Direct':
					start_time = time.time()
					download_the_link(alias)
					print "Download time :",(time.time()-start_time)
			else:
				if hops_are_not_same is False:
					print "Hops are same.Latency is now for criteria.."
				print "Best route is from "+rtt_best
				download_from = rtt_best
				if rtt_best=='Direct':
					start_time = time.time()
					download_the_link(alias)
					print "Download time :",(time.time()-start_time)
			
		else:
			print "Files not found"
			sys.exit("Exiting")
		
	else:
		print(s)
		sys.exit("Exiting")

Main()

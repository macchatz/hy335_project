import sys,os
import socket
import subprocess
import socket
import threading
import time
import struct
import SocketServer
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import hashlib

lock = threading.Lock()
REC_BUFF = 1024
Address =""
sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def traceroute(server,filename):
	with lock:
		ttl=1
		port=80
		pr = filename
		for ttl in range(1,30):
			s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			s.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,int(ttl))
			s.settimeout(1)
			try:
				s.connect((server,port))
			except (socket.error , socket.timeout) as err:
				print "TTL=",ttl 
				s.close()
				continue
			print "TTL = ",ttl
			
			pr.write('server Hops = '+str(ttl))
			pr.close()
			
			break
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
class CustThread(threading.Thread):
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
	
	return cipher

def decrypt_v(message,key):
    decrepted = AES.new(str(key)[:32])
    detagged = decrepted.decrypt(base64.b64decode(message))
    
    text = detagged.rstrip("\0")
    
    return str(text)

def Wait_for_Connection(sock,host,port,msg):

	sock.listen(1)


	while True:
		print host," is waiting for connection in port ",port
		connection,client_address = sock.accept()
		try:
			data = connection.recv(REC_BUFF)
			
			if data:
				print 'Sending data back to the client'
				
				connection.sendall(msg)
				global Address
				Address = client_address[0]
			else:
				print 'no more data from',client_address
				
		finally:
			
			break

	return data

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

private_key,public_key = generate_keys() #paragw ta private-public keyes
bring = str(socket.getfqdn())
host = bring.split(".")[0]
with open("files/relay_nodes.txt") as in_file:
	for line in in_file:
		if host in line:
			port = int(line.split(",")[2])
			break
sock.bind (('',port))
msg = public_key

clients_public_key = Wait_for_Connection(sock,host,port,msg) #pairnw to public_key toy client kai tou stelnw to diko mou
print "Clients public key is :",clients_public_key
verify_plain = Hash_string("password")
print "Hash is : "+verify_plain
verify_encrypted = encrypt(verify_plain,clients_public_key)
print "Encoded : ",str(verify_encrypted)
msg = str(verify_encrypted)
check = decrypt_v(verify_encrypted,clients_public_key)
print "Decrypt :",str(check)

data= Wait_for_Connection(sock,host,port,msg)#perimenw to ok gia na steilw to signature
print data
#if data 

pings,server= Wait_for_Connection(sock,host,port,msg).split(" ")
print "Server is:",server
print "Pings are:",pings
print "Client is:",Address

pingD=open(host+"_ping_results.txt","w+")
trcD = open(host+"_traceroute.txt","w+")
ping_d = CustThread("ping",server,pings,pingD)
traceroute_d = CustThread("traceroute",server,0,trcD)


ping_d.start()
traceroute_d.start()

ping_d.join()
rtt=0
with open (host+"_ping_results.txt", 'rt') as in_file:  # Open file lorem.txt for reading of text data.
	for line in in_file: # Store each line in a string variable "line"
		if "rtt" in line:
			rtt = rtt+float(line.split("/")[4])


rtt=str(float(rtt)/int(pings))



pingD.close()




traceroute_d.join()
trcD.close()
with open (host+"_traceroute.txt", 'rt') as in_file:  # fOpen file lorem.txt for reading of text data.
	for line in in_file:
		Hops = str(line.split(" ")[3]) 
		break 	

if len(Hops) is 1:
	Hops = Hops+' '
if len(rtt) > 6:
	rtt = rtt[:6]
elif len(rtt)<6:
	for i in range(1,6-len(rtt)):
		rtt = rtt+'0'
print "RTT_Direct = ",rtt
print " Hops =",Hops
msg = host+","+rtt+","+Hops
print msg
#send_to_client(Hops,rtt,int(new_port),Address)

sock.listen(1)

while True:
	print host," is waiting for connection in port ",port
	connection,client_address = sock.accept()
	try:
		data2 = connection.recv(REC_BUFF)
		print 'received', data2
		if data2:
			print 'Sending data back to the client'
			
			print msg
			connection.sendall(msg)
			
		else:
			print 'no more data from',client_address
			
	finally:
		
		break
connection.close()

import socket
import Crypto
import sys
import pickle
import select
import base64


from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def retrieveClientPublicKey():	
	try:
		f = open("./.client/client_rsa.pub", "r")
		privateKey = RSA.importKey(f.read())
		f.close()

	except (OSError, IOError) as e:
		sys.stderr.write("Failed to open client_rsa: %s \n" % e)
		sys.exit(1)	
	return privateKey


def retrieveServerPrivateKey():
	try:
		f = open("./.server/server_rsa", "r")
		publicKey = RSA.importKey(f.read())
		f.close()

	except (OSError, IOError) as e:
		sys.stderr.write("Failed to open server_rsa: \n")
		sys.exit(1)	
	return publicKey

#Used to get data over socket from client
def getData(portNumber):

	whole = ""
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server_socket.bind(("127.0.0.1", portNumber))
	server_socket.listen(1)
	print "Listening on port: %d" % portNumber
	read_list = [server_socket]
	while True:
	    readable, writable, errored = select.select(read_list, [], [])
	    for s in readable:
	        if s is server_socket:
	            client_socket, address = server_socket.accept()
	            read_list.append(client_socket)
	            print "Connection from", address
	        else:
	            data = s.recv(1024)
	            if data:
	                whole += data
	            else:
	            	client_socket.close()
	                s.close()
	                read_list.remove(s)
	                client_socket.close()
	                return whole

#PKCS7, Unpadding
def unpad(s):
    return s[:-ord(s[len(s)-1:])]


def main():
	total = len(sys.argv)
	if total != 3:
		sys.stderr.write(" \n \n Usage: python client.py [port number] [mode] \n \n")
		sys.exit(1)	

	unpaded = ""
	portNumber = int(sys.argv[1])
	mode = sys.argv[2]
	host = socket.gethostname()
	data  = getData(portNumber)
	dataList = data.split("MAGIC")
	unpickled = []
	#for element in dataList:
	#	unpickled.append(pickle.loads(element))

	encryptedKey = pickle.loads(dataList[0])
	
	if mode == 't':
		encryptedFile = dataList[1]
		with open("encryptedFile", "w") as efile:
			efile.write(encryptedFile)

	elif mode == 'u':
		try:
			with open("fakefile", "r") as ffile:
				encryptedFile = ffile.read()
		except IOError as e:
			sys.stderr.write("The program is running in untrusted mode. Couldn't file fake file please provide one! \n")
			sys.exit(1)	
	else:
		sys.stderr.write("The given mode is not correct! \n")
		sys.exit(1)

	#hash the file and check if it matches signature and it can be verified.
	hashedData = SHA256.new(encryptedFile).hexdigest()
	signature = pickle.loads(dataList[2])

	#retrieve servers private key to decrypt the sent encrypted key
	privKey = retrieveServerPrivateKey()
	decryptedKey = privKey.decrypt(encryptedKey)

	try:
		enc = base64.b64decode(encryptedFile)
		iv = enc[:16]
		cipher = AES.new(decryptedKey, AES.MODE_CBC, iv)
	except:
		print "Decryption and decoding failed. Probabily fakefile was given."
		print "Now checking the padding."

	try:
		#unpad the decrypted cipher text.
		unpaded = unpad(cipher.decrypt(enc[16:]))
	except:
		print "Unpadding procedure also failed. Checking signature as last resort"

	clientPublicKey = retrieveClientPublicKey()

	#verify signature
	if clientPublicKey.verify(hashedData, signature):
		print "Verification passed. The decrypted file is now being dumped."
		with open("decryptedfile", "w") as dfile:
			dfile.write(unpaded)
	else:
		print "Verification failed. Signatures do not match. Fakefile detected!"



if __name__== "__main__":
  main()
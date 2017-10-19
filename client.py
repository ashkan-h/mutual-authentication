import Crypto
import sys
import socket
import pickle
import base64


from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from socket import error as socket_error


BS = 16
def retrieveClientPrivateKey():	
	try:
		f = open("./.client/client_rsa", "r")
		privateKey = RSA.importKey(f.read())
		f.close()
	except:
		sys.stderr.write("Failed to open private key file for client. Make sure key pairs are generated.\n")
		sys.exit(1)	
	
	return privateKey


def retrieveServerPublicKey():
	try:
		f = open("./.server/server_rsa.pub", "r")
		publicKey = RSA.importKey(f.read())
		f.close()
	except IOError, e:
		sys.stderr.write("Failed to open server public key file. Make sure key pairs are generated. \n")
		sys.exit(1)	
	return publicKey

#Pad the data using PKCS7 standard
def pad(s):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

total = len(sys.argv)
if total < 4:
	sys.stderr.write("\n Usage: python client.py [password] [filepath] [server ip] [port number] \n \n ")
	sys.exit(1)	

password = str(sys.argv[1])
filepath = str(sys.argv[2])
serverIP = str(sys.argv[3])
portNumber = int(sys.argv[4])


if password < 16:
	sys.stderr.write("Password needs to be exactly 16 characters")
	sys.exit(1)


filearg = open(filepath, "r")
data = pad(filearg.read())
filearg.close()


#Encrypt the password
serverPublicKey = retrieveServerPublicKey()
encryptedKey = serverPublicKey.encrypt(password, 32)

#Encrypt the file
mode = AES.MODE_CBC
iv = Random.new().read(AES.block_size)
encryptor = AES.new(password, mode, IV=iv)
encryptedFile = encryptor.encrypt(data)
finalEnc = base64.b64encode(iv + encryptedFile)

#hash the file
hashedData = SHA256.new(finalEnc).hexdigest()

#sign the hashed data
privateKey = retrieveClientPrivateKey()
signature = privateKey.sign(hashedData, '')

#make connection now:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.connect((serverIP, portNumber))
	s.sendall(pickle.dumps(encryptedKey))
	s.sendall("MAGIC")
	s.sendall(finalEnc)
	s.sendall("MAGIC")
	s.sendall(pickle.dumps(signature))
	s.close()

except socket.error, exc:
	print "Caught exception socket.error : %s" % exc
	sys.stderr.write("Failed to connect to server: \n")
	sys.exit(1)

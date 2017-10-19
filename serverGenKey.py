from Crypto.PublicKey import RSA
import os
import sys

cwd = os.getcwd()
client_dir = os.path.join(cwd, ".server")

try:
	os.mkdir(client_dir)
except:
	sys.stderr.write("Failed to make \".server\" directory. It might already exist. \n")
	sys.exit(1)


private = RSA.generate(2048)
public  = private.publickey()


serverPrivatefile = open("./.server/server_rsa", "w")
serverPrivatefile.write(private.exportKey()) #save exported private key
serverPrivatefile.close()

serverPublicfile = open("./.server/server_rsa.pub", "w")
serverPublicfile.write(public.exportKey())
serverPublicfile.close()

print "The key pair for the server is now generated"
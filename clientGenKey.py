from Crypto.PublicKey import RSA
import os
import sys

cwd = os.getcwd()
client_dir = os.path.join(cwd, ".client")

try:
	os.mkdir(client_dir)
except:
	sys.stderr.write("Failed to make \".client\" directory. It might already exist\n")
	sys.exit(1)


private = RSA.generate(2048)
public  = private.publickey()


clientPrivatefile = open("./.client/client_rsa", "w")
clientPrivatefile.write(private.exportKey()) #save exported private key
clientPrivatefile.close()

clientPublicfile = open("./.client/client_rsa.pub", "w")
clientPublicfile.write(public.exportKey())
clientPublicfile.close()

print "The key pair for the client is now generated"

1) To install the libraries: 
	The python program relies on the pycrypto module. I was bored thought it would be cool to check it out. It can be simply downloaded by via Pip:
	sudo apt-get install python-dev
	sudo pip install pycrypto


2) To generate the public and private key pair for both client and the server there you need to run the below scripts:
	python serverGenKey.py
	python clientGenKey.py

	The two scripts create two folders ssh style with the public and private key in them: ".server" and ".client"
	after running serverGen and clientGen, if we do "ls -la":
	there two "hidden" directories ".client" and ".server"

	Server and Client have two important functions each:
	In the server we have:

	retrieveClientPublicKey and retrieveServerPrivateKey. 
        The first one uses the public key of the client stored in ".client" (i.e., ./.client/client_rsa.pub). It is used to verify the 
	encrypted file. By using it as:

	clientPublick = retrieveClientPublickKey()
	clientPublicKey.verify(hashedData, signature)

	The retrieve server private key takes the file in ./.server/server_rsa and then its used to decrypt the encrypted key. 
	privKey = retrieveServerPrivateKey()
	decryptedKey = privKey.decrypt(encryptedKey)

	Similarly in client we use retrieveClientPrivateKey , retrieveServerPublicKey in the similar fashion to encrypt the
	shared password using the server's public key, and sign the encrypted file using client's private key.


3) Run the program as below:
	python server.py 4444 u
	OR
	python server.py 4444 t

	after running the server, you can run the client in another session/terminal:
	
	python client.py 1234567891234567 ~/secret.txt 127.0.0.1 4444

        In the above example, the first arguement is the password, which is obviously super strong. Which will be used as a shared key
	for AES encryption, the second arguement is the file that we are encrypting. Again, this was done to see how pycrypto works. So no security here, think of it as a joke maybe?


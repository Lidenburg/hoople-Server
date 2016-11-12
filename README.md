# Hoople Server
The source code for the chat service codenamed __hoople__.

## What is this?
This is the source code to a chat server, written in C.

## Is it usable?
No. There are many things that are not implemented or working yet. It is very much a work in progress.

## What is the purpose of this?
The purpose of hoople is to provide a chat service that focuses on security and message integrity.

## Okay, I see a server but where's the client?
https://github.com/Lidenburg/hoople-Client

# Technical details

## User management
Hoople is designed to use certificates rather than passwords, that means that the user has to generate a key and create a 
certificate signing request, and the server operator then has to sign that request and send back the certificate and save the 
serial number along with a username that the user wished for.
The server operator then saves the serialnumber from the certificate and the username in the file users.txt (see the file for 
format).

## Cryptography
Hoople uses TLS to communicate securely with the server, it is designed to specifically only allow TLS and not SSL.

The idea is that the messages users send to the server are encrypted by TLS, and that the actual contents of what the users
write to eachother is encrypted with some method of 256 bit AES (the Encrypt function is currently set to GCM). That way the user
doesn't even necessarily have to trust the server, since it can't read or modify the contents of the message, the only information
the server can see is who the message is to and what type of message it is.

This requires that users have (yet another) private key, and since the server could easily be modified to MitM a DH key exchange
users have to get ahold of eachothers public keys outside of the application. I have an idea that ECDH should be used for this,
and I have a POC written for it already, it just needs to be implemented.

## Todo's
+ Change the structure of a message so we don't encrypt the username of the recipient
+ Implement the 2nd layer of crypto
+ Implement a way for users to add eachother from public keys
+ Many, many more

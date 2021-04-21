# EncryptDecryptHandler

## Comments
The execution is available from jdk version 14 
To run program easy - double click on run.bat - (the command wrote in run.txt)
After creating the keystores - the files were copied to the projects.

## Encryption
The decryption program reads as input the encrypted.txt and conf.txt 
From conf.txt it decodes the signature bytes , IV bytes and encrypted symmetric key bytes ,thus he can decrypt the symmetric key using Decryptor RSA private key and the data itself. (using same algorithms and modes as above).
It verifies the signature using the Encrypts certificate public key  with the encrypted data - on match will create as output decrypt.txt file otherwise prints error

### Decryption
The decryption program reads as input the encrypted.txt and conf.txt 
From conf.txt it decodes the signature bytes , IV bytes and encrypted symmetric key bytes ,thus he can decrypt the symmetric key using Decryptor RSA private key and the data itself. (using same algorithms and modes as above).
It verifies the signature using the Encrypts certificate public key  with the encrypted data - on match will create as output decrypt.txt file otherwise prints error


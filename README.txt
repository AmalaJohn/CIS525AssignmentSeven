Assignment #7
==================================================================
Supported Chat Room Topics:

- General Chat
- Gaming
- KSU Football
- Study Group
- Tech Discussion

==================================================================
Setup Instructions

1. Copy the files to your own directory.

2. Modify inet.h to reflect the host you are currently logged into.
   Also, modify the port numbers to be used to reduce the likelihood
   of conflicting with another server.

3. Generate Certificates and Keys by running:	./generate_certs.sh

4. Compile the programs using "make".

==================================================================
Running Instructions

1. Start the server directory in the background: ./directoryServer5 &

2. Start a Chat Server. Replace <port> with port number of choice and <Room Name> with a supported chat room topic(see above):
./chatServer5 "<Room Name>" <port>

3. Start the client on the same or another host in the foreground: ./chatClient2

4. Connect to a chat room. The chat client will ask for ServerName, ServerIP, and ServerPort. Enter them in this format:
<Room Name>,<Chat Server IP>,<Chat Server Port>

Then you are set up to chat with others in the room!

5.Remember to kill the server before logging off.

==================================================================
Certificate Files

ca-cert.pem - Certificate Authority public certificate used by the chat clients, chat servers, and directory server to verify certificates are signed by the trusted CA.

ca-key.pem - Private key for the Certificate Authority, used to sign all other certificates.

Directory_Server-cert.pem - Certificate for the directory server. It proves the identity of the directory server to clients and chat servers during TLS handshake.

Directory_Server-key.pem - Private key for the directory server that decrypts messages and performs TLS authentication for the directory server.

Chat Room Certificates - Certificates for the chat servers that correspond to the room topics so clients can verify they are in the correct room.
(file names replace spaces in room names with underscores)
All chat room certificates: Gaming-cert.pem, General_Chat-cert.pem, KSU_Football-cert.pem, Study_Group-cert.pem, Tech_Disscusstion-cert.pem

Chat Room Keys - The private keys for each certificate that decrypt TLS messages and used for authentication.
(file names replace spaces in room names with underscores)
All chat room keys: Gaming-key.pem, General_Chat-key.pem, KSU_Football-key.pem, Study_Group-key.pem, Tech_Discussion-key.pem


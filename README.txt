Assignment #5 - ASSIGNMENT TITLE

==================================================================
Group Members

Sebastian Rhoton - Certificate Infrastructure & Setup
- Generating certificates and keys using OpenSSL
- Creating an automated certificate generation script
- Setting up the Certificate Authority
- Documenting certificate structure and usage

Amala John - Directory Server (directoryServer5.c)
- Adding SSL/TLS 1.3 support to directory server
- Adding ability to accept encrypted connections from chat clients and chat servers
- Verifying chat server certificates matched our claimed topics
- Handling REGISTER and QUERY commands over TLS

Jacob Schmitt - Chat Server (chatServer5.c)
- Adding SSL/TLS 1.3 support to chat server
- Adding ability to accept encrypted connections from chat clients
- Allowing connection to directory server with encryption
- Selecting correct certificate based on chat room topic
- allowing encrypted messages to be broadcasted to all clients

Jesus Castro-Garcia - Chat Client (chatClient5.c)
- Adding SSL/TLS 1.3 support to chat client
- Connecting to directory server and selected chat servers with encryption and verifying certificates
- Handling sending/receiving encrypted messages
- Rejecting conections with invalid or mismatched certificates

Ella Foxhoven - Integration, Testing & Documentation
- Writing comprehensive README with all group member names
- Performing integration testing
- Documenting all error scenarios
- Preparing final submission

==================================================================
Supported Chat Room Topics:

- General Chat
- Gaming
- KSU Football
- Study Group
- Tech Discussion

==================================================================
Setup Instructions

1. Log into CSLinux.

2. Generate Certificates and Keys by running:	./generate_certs.sh

3. Compile the programs using "make".

==================================================================
Running Instructions

1. Start the Directory Server by using its hard-coded port number, certificate, and key:
./directoryServer5 50967 Directory_Server-cert.pem Directory_Server-key.pem ca-cert.pem

2. Start a Chat Server. Replace <port> with port number of choice and <Room Name> with a supported chat room topic:
./chatServer5 "<Room Name>" <port>

3. Start the Chat Client with the Directory Server's IP and port number:
./chatClient5 <Directory Server IP> 50967 ca-cert.pem

4. Connect to a chat room. The chat client will ask for ServerName, ServerIP, and ServerPort. Enter them in this format:
<Room Name>,<Chat Server IP>,<Chat Server Port>

Then you are set up to chat with others in the room!

==================================================================
Security Features

- All communication between servers and clients is protected using TLS 1.3 encryption
- Every connection in the system is authenticated using certificates signed by the project's Certificate Authority
- The system will fail gracefully when presented with certificates whose CN doesn't match its room topic.
- The connection will be rejected when there is an invalid or untrusted certificate.
- If there are missing certificate or key files an error message is printed and exits before starting.

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

==================================================================
Error Handling

- Certificate Files Missing
After renaming the Directory_Server-cert.pem file and trying to start the directory server I got this error message:
ellafoxhoven@cougar:~/CIS525_Assignments/CIS525AssignmentSeven$ ./directoryServer5 50967 Directory_Server-cert.pem Directory_Server-key.pem ca-cert.pem
40474CF9D77F0000:error:80000002:system library:file_ctrl:No such file or directory:../crypto/bio/bss_file.c:297:calling fopen(Directory_Server-cert.pem, r)
40474CF9D77F0000:error:10080002:BIO routines:file_ctrl:system lib:../crypto/bio/bss_file.c:300:
40474CF9D77F0000:error:0A080002:SSL routines:SSL_CTX_use_certificate_file:system lib:../ssl/ssl_rsa.c:291:
The directory server detected the missing certificate, ended the startup, and displayed the correct error message.

- Connection Refused/Network Errors
When the client cannot connect to a chat server because nothing is listening, it stops trying to connect and an error message is printed saying the connection failed.
No registered chat rooms right now
Enter ServerName,ServerIP,ServerPort: Gaming,129.130.10.43,5195
Connecting to chat server 'Gaming' at 129.130.10.43,5195
client: can't connect to server: Connection refused

- Invalid User Input
When receiving user input formatted incorrectly the program prints out the correct error message and stops the connection.
Enter ServerName,ServerIP,ServerPort: Gaming,129.130.10.39,notaport
Invalid input format. Expected: ServerName,ServerIP,ServerPort

Enter ServerName,ServerIP,ServerPort: Gaming,999.999.999.999,55555
Connecting to chat server 'Gaming' at 999.999.999.999,55555
client: can't connect to server: Network is unreachable

==================================================================
Integration Testing

- Directory server starts successfully:
Running "./directoryServer5 50967 Directory_Server-cert.pem Directory_Server-key.pem ca-cert.pem" successfully starts the directory server
and waits for connections. After starting a chat server it shows on the directory server: "Registered chat server: KSU Football at 129.130.10.39:51955"
Showing that the directory server is active and running correctly.

- Multiple chat servers register with different topics:
After starting two chat servers I was able to successfully send chats on both at the same time.

- Clients can query and see all rooms:
Starting two chat servers and then running "./chatClient5 129.130.10.39 50967 ca-cert.pem" in the chat client terminal
allows me to see both of the chat servers, their ip address, and port number as shown below.
ROOM: Gaming at 129.130.10.39,51950
ROOM: KSU Football at 129.130.10.39,51955

- Multiple clients can join rooms and chat:
After connecting two chat clients to the same chat server I was able to see all chats going through with the correct username.

==================================================================
Test Result Documentation

Log of successful multi-client chat:
Connecting to chat server 'KSU Football' at 129.130.10.39,51955
Enter your username: ella
Username set to: ella
Welcome ella! You are the only one here.
mike has joined the chat.
mike: Hello! I am mike
Hi mike!
mike: I received your message

Log of certificate verification working:
- Directory Server Log
ellafoxhoven@cougar:~/CIS525_Assignments/CIS525AssignmentSeven$ ./directoryServer5 50967 Directory_Server-cert.pem Directory_Server-key.pem ca-cert.pem
Registered chat server: KSU Football at 129.130.10.39:51955
Registered chat server: Gaming at 129.130.10.39:51950
- Chat Client Log
ellafoxhoven@cougar:~/CIS525_Assignments/CIS525AssignmentSeven$ ./chatClient5 129.130.10.39 50967 ca-cert.pem
ROOM: KSU Football at 129.130.10.39,51955
Enter ServerName,ServerIP,ServerPort: KSU Football,129.130.10.39,51955               
Connecting to chat server 'KSU Football' at 129.130.10.39,51955
Enter your username: ella
Username set to: ella
Welcome ella! You are the only one here.

Log of rejected invalid certificate:

BUG:
ellafoxhoven@cougar:~/CIS525_Assignments/CIS525AssignmentSeven$ ./chatClient5 129.130.10.39 50967 wrong-ca.pem
ROOM: KSU Football at 129.130.10.39,51955
Enter ServerName,ServerIP,ServerPort: KSU Football,129.130.10.39,51955
Connecting to chat server 'KSU Football' at 129.130.10.39,51955
Enter your username: ella
Username set to: ella
Welcome ella! There are 1 other users here.


fix client to require certificate validation

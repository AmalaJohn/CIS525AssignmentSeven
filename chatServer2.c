#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include "inet.h"
#include "common.h"


#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tvar)               \
    for ((var) = LIST_FIRST((head));                            \
         (var) && ((tvar) = LIST_NEXT((var), field), 1);        \
         (var) = (tvar))
#endif

struct client {
	int socketfd;
	char username[31];
	LIST_ENTRY(client) entries;
};
LIST_HEAD(client_list, client) clients;


int username_exists(const char *name) {
    struct client *c;
    LIST_FOREACH(c, &clients, entries) {
        if (c->username[0] != '\0' && strncmp(c->username, name, MAX) == 0) {
            return 1; // already taken
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Must initialize with Chat Room Name and Port Number\n");
		return EXIT_FAILURE;
	}

	char CHAT_ROOM_NAME[31] = {'\0'};
	snprintf(CHAT_ROOM_NAME, sizeof(CHAT_ROOM_NAME), "%.30s", argv[1]);

	int CHAT_SERV_TCP_PORT = 0;
	sscanf(argv[2], "%d", &CHAT_SERV_TCP_PORT);
	if (CHAT_SERV_TCP_PORT == 0) {
		fprintf(stderr, "Port number must be an integer between 49152 and 65535\n");
		return EXIT_FAILURE;
	}
	else if (CHAT_SERV_TCP_PORT < 49152 || CHAT_SERV_TCP_PORT > 65535) {
		fprintf(stderr, "Port number must be between 49152 and 65535\n");
		return EXIT_FAILURE;
	}

	int dir_sockfd;     /*socket to contact directoryServer*/
	int sockfd;			/* Listening socket for clients*/
	struct sockaddr_in cli_addr, serv_addr, dir_addr;
	fd_set readset;

	/*Acting like a client now*/

	/* Set up the address of the server to be contacted. */
	memset((char *) &dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family			= AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);	/* hard-coded in inet.h */
	dir_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Create a socket (an endpoint for communication). */
	if ((dir_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(dir_sockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
		perror("client: can't connect to server");
		return EXIT_FAILURE;
	}

	char buf[MAX];
	snprintf(buf, MAX, "USERNAME:%s:%d\n", CHAT_ROOM_NAME, CHAT_SERV_TCP_PORT);

	if (write(dir_sockfd, buf, strnlen(buf, MAX)+1) < 0) {
		perror("client: failed to send username");
		return EXIT_FAILURE;
	}

	/*Acting like a server now*/


	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Add SO_REUSEADDRR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		return EXIT_FAILURE;
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	serv_addr.sin_port			= htons(CHAT_SERV_TCP_PORT);			

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	listen(sockfd, 5);


	LIST_INIT(&clients);


	for (;;) {
		/* Initialize and populate your readset and compute maxfd */
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		/* We won't write to a listening socket so no need to add it to the writeset */
		int max_fd = sockfd;

		/* FIXME: Populate readset with ALL your client sockets here,
		 * e.g., using LIST_FOREACH */
		/* clisockfd is used as an example socket -- we never populated it so it's invalid */
		struct client *entry;
        LIST_FOREACH(entry, &clients, entries){
			FD_SET(entry->socketfd, &readset);
			if (entry->socketfd > max_fd)
				max_fd = entry->socketfd;
		}

		/* Compute max_fd as you go */

		if (select(max_fd+1, &readset, NULL, NULL, NULL) > 0) {

			/* Check to see if our listening socket has a pending connection */
			if (FD_ISSET(sockfd, &readset)) {
				/* Accept a new connection request */
				socklen_t clilen = sizeof(cli_addr);
				int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
				if (newsockfd < 0) {
					perror("server: accept error");
					close (newsockfd);
					close(sockfd);
					return EXIT_FAILURE;
				}
				/* FIXME: Add newsockfd to your list of clients -- but no nickname yet */
				struct client *new_client = malloc(sizeof(struct client));
				if (new_client != NULL){
					new_client->socketfd = newsockfd;
					new_client->username[0] = '\0';
					LIST_INSERT_HEAD(&clients, new_client, entries);
				}
				else{
					close(newsockfd);
					fprintf(stderr, "server: malloc error");
					close(sockfd);
					return EXIT_FAILURE;
				}
				/* We can't immediately read(newsockfd) because we haven't asked
				* select whether it's ready for reading yet */
			}
			/* TODO: Check ALL your client sockets, e.g., using LIST_FOREACH */
			/* clisockfd is used as an example socket -- we never populated it so
			* it's invalid */
			struct client *entry1;
			struct client *tmp;
			LIST_FOREACH_SAFE(entry1, &clients, entries,tmp) {
			/* Note that this is a seperate if, not an else if -- multiple sockets
			* may become ready */
				if (FD_ISSET(entry1->socketfd, &readset)) {
					//fprintf(stderr, "socket %d is ready\n", entry1->socketfd); //DEBUG
					/* FIXME: Modify the logic */
					char buf[MAX];

					/* Read the request from the client */
					/* FIXME: This may block forever since we haven't asked select
						whether clisockfd is ready */
					ssize_t nread = read(entry1->socketfd, buf, MAX);
					if (nread == 0) {
						if (entry1->username[0] != '\0') {
							char msg[MAX];
							snprintf(msg, MAX, "%s has left the chat.\n", entry1->username);
							struct client *other;
							LIST_FOREACH(other, &clients, entries) {
								if (other != entry1 && other->username[0] != '\0')
									write(other->socketfd, msg, strnlen(msg, MAX)+1);
							}
						}
						close(entry1->socketfd);

						LIST_REMOVE(entry1, entries);
						free(entry1);
					}
					else if (nread < 0) {
						/* Not every error is fatal. Check the return value and act accordingly. */
						if( errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
							fprintf(stderr, "%s:%d Error reading from client\n", __FILE__, __LINE__);
							close (entry1->socketfd);
							LIST_REMOVE(entry1, entries);
							free(entry1);
							return EXIT_FAILURE;
						}
					}
					else{
						//fprintf(stderr, "Received from client: %s\n", buf); //DEBUG
						if (nread < MAX){
							buf[nread] = '\0';  // Null-terminate the string
						} else {
							buf[MAX - 1] = '\0'; // Ensure null-termination
						}
						char command[32], payload[92];
						if (sscanf(buf, "%31[^:]:%91[^\n]%*[^\n]", command, payload) == 2) {
							//fprintf(stderr, "Parsed command='%s', payload='%s'\n", command, payload);

							if (strncmp(command, "USERNAME",8) == 0) {
								if (entry1->username[0] != '\0') {
									// already registered
									write(entry1->socketfd, "ERROR: Already registered\n", 27);
								}
								else if (username_exists(payload)) {
									write(entry1->socketfd, "ERROR: Username already taken\n", 30);
									close(entry1->socketfd);
									LIST_REMOVE(entry1, entries);
									free(entry1);
								}
								else {
									snprintf(entry1->username, sizeof(entry1->username), "%.30s", payload);
									char msg[MAX];;

									int count = 0;
									snprintf(msg, MAX, "%s has joined the chat.\n", entry1->username);
									struct client *other;
									LIST_FOREACH(other, &clients, entries) {
										if (other != entry1 && other->username[0] != '\0'){
											write(other->socketfd, msg, strnlen(msg, MAX));
											count++;
										}
									}

									if(!count){
										snprintf(msg, MAX, "Welcome %s! You are the only one here.\n", entry1->username);
									}
									else{
										snprintf(msg, MAX, "Welcome %s! There are %d other users here.\n", entry1->username, count);
									}
									write(entry1->socketfd, msg, strnlen(msg, MAX));
								}
							}
							else if (strncmp(command, "MSG", 3) == 0) {
								if (entry1->username[0] == '\0') {
									write(entry1->socketfd, "ERROR: Must register username first\n", 37);
								}
								else {
									char msg[MAX];
									snprintf(msg, MAX, "%.30s: %.60s\n", entry1->username, payload);
									struct client *other;
									LIST_FOREACH(other, &clients, entries) {
										if (other != entry1 && other->username[0] != '\0')
											write(other->socketfd, msg, strnlen(msg, MAX));
									}
								}
							}

						}
					}
				}
			}
		}
		else {
			if (errno == EINTR) {
				// Interrupted by a signal (like SIGINT), just restart loop
				continue;
			} else {
				perror("select error");
				break;
			}
		}
	}
	close(sockfd);
	close(dir_sockfd);
}

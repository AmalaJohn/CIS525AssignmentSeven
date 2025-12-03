#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

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
	SSL *ssl;                    /* TLS handle for this connection */
	char username[MAX];
	int client_port;
	struct in_addr client_ip;
	int is_server;
	LIST_ENTRY(client) entries;
};
LIST_HEAD(client_list, client) clients;


/* tiny helper to set non-blocking (minimize added helpers as requested) */
static int make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

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
	int sockfd;			/* Listening socket */
	struct sockaddr_in cli_addr, serv_addr;
	fd_set readset;

	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* Create SSL context (server) */
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		fprintf(stderr, "Unable to create SSL context\n");
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}
	/* Enforce TLS 1.3 only */
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

	/* Do not require client certs (assignment said client auth not required) */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	/* Load server cert and key */
	if (SSL_CTX_use_certificate_file(ctx, "Directory_Server-cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "Directory_Server-key.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}
	/* Load CA (for thoroughness; not used for client auth here) */
	if (!SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL)) {
		ERR_print_errors_fp(stderr);
		/* not fatal for this assignment, but warn */
	}

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Add SO_REUSEADDR option */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		return EXIT_FAILURE;
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= inet_addr(SERV_HOST_ADDR);
	//serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);	/* hard-coded in inet.h */
	serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	listen(sockfd, 5);

	/* make listening socket non-blocking so accept won't block forever */
	if (make_nonblocking(sockfd) < 0) {
		perror("make_nonblocking listen socket");
		/* not fatal, continue */
	}

	LIST_INIT(&clients);

	for (;;) {
		/* Initialize and populate your readset and compute maxfd */
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		/* We won't write to a listening socket so no need to add it to the writeset */
		int max_fd = sockfd;

		/* Populate readset with ALL your client sockets here */
		struct client *entry;
        LIST_FOREACH(entry, &clients, entries){
			FD_SET(entry->socketfd, &readset);
			if (entry->socketfd > max_fd)
				max_fd = entry->socketfd;
		}

		if (select(max_fd+1, &readset, NULL, NULL, NULL) > 0) {

			/* Check to see if our listening socket has a pending connection */
			if (FD_ISSET(sockfd, &readset)) {
				/* Accept a new connection request */
				socklen_t clilen = sizeof(cli_addr);
				int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

				if (newsockfd < 0) {
					perror("server: accept error");
					/* on accept error, continue server loop (don't exit entirely) */
				} else {
					/* allocate client and set up TLS */
					struct client *new_client = malloc(sizeof(struct client));
					if (new_client != NULL){
						new_client->socketfd = newsockfd;
						new_client->is_server = 0;
						new_client->username[0] = '\0';
						new_client->client_ip = cli_addr.sin_addr; /* store peer ip now */
						new_client->ssl = SSL_new(ctx);
						if (!new_client->ssl) {
							ERR_print_errors_fp(stderr);
							close(new_client->socketfd);
							free(new_client);
						} else {
							SSL_set_fd(new_client->ssl, newsockfd);
							/* make non-blocking so TLS operations can return WANT_READ/WANT_WRITE */
							if (make_nonblocking(new_client->socketfd) < 0) {
								/* not fatal, continue */
							}
							LIST_INSERT_HEAD(&clients, new_client, entries);
						}
					}
					else{
						close(newsockfd);
						fprintf(stderr, "server: malloc error");
					}
				}
				/* We can't immediately read(newsockfd) because we haven't asked
				* select whether it's ready for reading yet */
			}
			/* Check ALL your client sockets */
			struct client *entry1;
			struct client *tmp;
			LIST_FOREACH_SAFE(entry1, &clients, entries,tmp) {
				/* Note: multiple sockets may become ready */
				if (FD_ISSET(entry1->socketfd, &readset)) {
					/* Perform TLS handshake if not yet finished */
					if (!SSL_is_init_finished(entry1->ssl)) {
						int ret = SSL_accept(entry1->ssl);
						if (ret <= 0) {
							int err = SSL_get_error(entry1->ssl, ret);
							if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
								/* handshake in progress; continue to next client */
								continue;
							} else {
								ERR_print_errors_fp(stderr);
								/* remove client */
								SSL_free(entry1->ssl);
								close(entry1->socketfd);
								LIST_REMOVE(entry1, entries);
								free(entry1);
								continue;
							}
						}
						/* Handshake finished; continue so we can read request on next select */
						continue;
					}

					/* Read the request from the client over TLS */
					char buf[MAX+1];
					int nread = SSL_read(entry1->ssl, buf, MAX);
					if (nread <= 0) {
						int err = SSL_get_error(entry1->ssl, nread);
						if (nread == 0 || (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)) {
							/* connection closed or fatal error */
							SSL_shutdown(entry1->ssl);
							SSL_free(entry1->ssl);
							close(entry1->socketfd);
							LIST_REMOVE(entry1, entries);
							free(entry1);
						}
						/* else WANT_READ/WRITE -> try later */
					}
					else {
						buf[nread] = '\0';
						char command[32];
						char payload[92];
						int port = 0;
						if (sscanf(buf, "%31[^:]:%63[^:]:%d", command, payload, &port) == 3) {
							if (strncmp(command, "USERNAME",8) == 0) {
								if (username_exists(payload)) {
									const char *msg = "ERROR: Username already taken\n";
									SSL_write(entry1->ssl, msg, strnlen(msg));
									SSL_shutdown(entry1->ssl);
									SSL_free(entry1->ssl);
									close(entry1->socketfd);
									LIST_REMOVE(entry1, entries);
									free(entry1);
								}
								else {
									snprintf(entry1->username, MAX, "%s", payload);
									entry1->is_server = 1;
									entry1->client_port = htons(port);
									
									fprintf(stderr, "Registered chat server: %s at %s:%d\n",
										entry1->username,
										inet_ntoa(entry1->client_ip),
										port);
								}
							}
							else if (strncmp(command, "CHAT", 4) == 0) {
								char response[MAX];
								int offset = 0;  // Keeps track of how many bytes we've written
								int remaining = MAX;
								int count = 0;

								struct client *server;
								LIST_FOREACH(server, &clients, entries) {
									if(server->is_server) {
										int written = snprintf(
										response + offset, remaining,
										"ROOM: %s at %s,%d\n",
										server->username,
										inet_ntoa(server->client_ip),
										ntohs(server->client_port)
										);

										if (written < 0 || written >= remaining) {
											perror("snprintf error or buffer full");
											break;
										}

										offset += written;
										remaining -= written;
										count++;
									}
									
								}

								if (count == 0) {
									snprintf(response, sizeof(response),
											"No registered chat rooms right now\n");
								}

								/* write only the used portion */
								SSL_write(entry1->ssl, response, strnlen(response));
							}	
							else {
								const char *msg = "Incorrect command\n";
								SSL_write(entry1->ssl, msg, strnlen(msg));
							}
						}
					}
				}
			}
		}
		else {
			if (errno == EINTR) {
				/* Interrupted by a signal (like SIGINT), just restart loop */
				continue;
			} else {
				perror("select error");
				break;
			}
		}
	}
	close(sockfd);
	SSL_CTX_free(ctx);
	return 0;
}

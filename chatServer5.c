#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include "inet.h"
#include "common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <errno.h>

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tvar)               \
    for ((var) = LIST_FIRST((head));                            \
         (var) && ((tvar) = LIST_NEXT((var), field), 1);        \
         (var) = (tvar))
#endif

struct client {
	int socketfd;
	SSL *ssl;
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

void init_openssl()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}


SSL_CTX *init_chat_server_ssl_context(const char *ca_file,
                                      const char *cert_file,
                                      const char *key_file)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) {
        fprintf(stderr, "Could not load CA file %s\n", ca_file);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Could not load cert file %s\n", cert_file);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Could not load key file %s\n", key_file);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Key and certificate do NOT match.\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}


void build_cert_paths(const char *topic, char *cert_path, char *key_path)
{
    char tmp[64];

    // Replace spaces with underscores
    int j = 0;
    for (int i = 0; topic[i] != '\0'; i++) {
        tmp[j++] = (topic[i] == ' ') ? '_' : topic[i];
    }
    tmp[j] = '\0';

    snprintf(cert_path, 128, "%s-cert.pem", tmp);
    snprintf(key_path, 128, "%s-key.pem", tmp);
}

SSL_CTX *init_directory_ssl_context(const char *ca_file)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) {
        fprintf(stderr, "Could not load CA file %s\n", ca_file);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

int verify_expected_subject(SSL *ssl, const char *expected_cn)
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "Peer did NOT provide a certificate.\n");
        return 0;
    }

    X509_NAME *subj = X509_get_subject_name(cert);
    char cn[256] = {0};

    int idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (idx < 0) {
        fprintf(stderr, "Certificate has NO CN field.\n");
        X509_free(cert);
        return 0;
    }

    X509_NAME_ENTRY *entry = X509_NAME_get_entry(subj, idx);
    ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
    strncpy(cn, (char *)ASN1_STRING_get0_data(data), sizeof(cn) - 1);

    X509_free(cert);

    if (strcmp(cn, expected_cn) != 0) {
        fprintf(stderr, "Certificate CN mismatch: expected '%s', got '%s'\n",
                expected_cn, cn);
        return 0;
    }

    return 1;
}

int tls_read_safe(SSL *ssl, char *buf, int size)
{
    int r = SSL_read(ssl, buf, size);

    if (r > 0) return r;

    int err = SSL_get_error(ssl, r);

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return -2;   // not fatal, try again

    if (err == SSL_ERROR_ZERO_RETURN)
        return 0;    // clean shutdown

    return -1;       // fatal TLS error
}

int tls_write_safe(SSL *ssl, const char *buf, int len)
{
    int r = SSL_write(ssl, buf, len);

    if (r > 0) return r;

    int err = SSL_get_error(ssl, r);

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return -2;

    return -1;
}



int main(int argc, char **argv)
{
	if (argc != 3){
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


	/* Build cert/key filenames based on chat room name */
    char certfile[128], keyfile[128];
    build_cert_paths(CHAT_ROOM_NAME, certfile, keyfile);

    /* Ensure cert/key exist before starting */
    if (access(certfile, F_OK) != 0 || access(keyfile, F_OK) != 0) {
        fprintf(stderr, "Missing certificate or key for topic '%s'\n", CHAT_ROOM_NAME);
        fprintf(stderr, "Expected files: %s and %s\n", certfile, keyfile);
        return EXIT_FAILURE;
    }

    /* Initialize OpenSSL and create contexts */
    init_openssl();
    SSL_CTX *server_ctx = init_chat_server_ssl_context("ca-cert.pem",
                                                       certfile,
                                                       keyfile);
    SSL_CTX *dir_ctx = init_directory_ssl_context("ca-cert.pem");

	int dir_sockfd;     /*socket to contact directoryServer*/
	int sockfd;			/* Listening socket for clients*/
	struct sockaddr_in cli_addr, serv_addr, dir_addr;
	fd_set readset;

	/*Acting like a client now*/

	/* Set up the address of the server to be contacted. */
	memset((char *) &dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family      = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);   /* directory server host (from inet.h) */
    dir_addr.sin_port        = htons(SERV_TCP_PORT); 	/* hard-coded in inet.h */

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
	snprintf(buf, MAX, "REGISTER:%s:%d\n", CHAT_ROOM_NAME, CHAT_SERV_TCP_PORT);

	SSL *dir_ssl = SSL_new(dir_ctx);
    if (!dir_ssl) {
        fprintf(stderr, "Failed to create SSL for directory connection\n");
        return EXIT_FAILURE;
    }
    SSL_set_fd(dir_ssl, dir_sockfd);

    if (SSL_connect(dir_ssl) <= 0) {
        fprintf(stderr, "TLS handshake with Directory Server failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(dir_ssl);
        return EXIT_FAILURE;
    }

    /* Verify Directory Server certificate CN = "Directory Server" */
    if (!verify_expected_subject(dir_ssl, "Directory Server")) {
        fprintf(stderr, "Directory Server certificate CN mismatch\n");
        SSL_shutdown(dir_ssl);
        SSL_free(dir_ssl);
        return EXIT_FAILURE;
    }

    if (SSL_write(dir_ssl, buf, strnlen(buf, MAX)) <= 0) {
        fprintf(stderr, "Failed to send REGISTER to Directory Server over TLS\n");
        SSL_shutdown(dir_ssl);
        SSL_free(dir_ssl);
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

		 int ready = select(max_fd + 1, &readset, NULL, NULL, NULL);
        if (ready > 0) {

            /* New incoming connection? */
            if (FD_ISSET(sockfd, &readset)) {
                socklen_t clilen = sizeof(cli_addr);
                int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) {
                    perror("server: accept error");
                } else {
                    struct client *new_client = malloc(sizeof(struct client));
                    if (new_client == NULL) {
                        fprintf(stderr, "server: malloc error\n");
                        close(newsockfd);
                    } else {
                        new_client->socketfd = newsockfd;
                        new_client->username[0] = '\0';

                        new_client->ssl = SSL_new(server_ctx);
                        if (!new_client->ssl) {
                            fprintf(stderr, "server: SSL_new failed\n");
                            close(newsockfd);
                            free(new_client);
                        } else {
                            SSL_set_fd(new_client->ssl, newsockfd);

                            if (SSL_accept(new_client->ssl) <= 0) {
                                fprintf(stderr, "server: TLS handshake with client failed\n");
                                ERR_print_errors_fp(stderr);
                                SSL_free(new_client->ssl);
                                close(newsockfd);
                                free(new_client);
                            } else {
                                LIST_INSERT_HEAD(&clients, new_client, entries);
                            }
                        }
                    }
                }
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
					int nread = tls_read_safe(entry1->ssl, buf, MAX);

                                        if (nread == -2) {
                                                /* SSL wants more IO, not fatal; try again later */
                                                continue;
                                        } else if (nread == 0) {
                                                /* Clean shutdown from client */
                                                if (entry1->username[0] != '\0') {
                                                        char msg[MAX];
                                                        snprintf(msg, MAX, "%s has left the chat.\n", entry1->username);
                                                        struct client *other;
                                                        LIST_FOREACH(other, &clients, entries) {
                                                                if (other != entry1 && other->username[0] != '\0')
                                                                        tls_write_safe(other->ssl, msg, strnlen(msg, MAX));
                                                        }
                                                }

                                                SSL_shutdown(entry1->ssl);
                                                SSL_free(entry1->ssl);
                                                close(entry1->socketfd);

                                                LIST_REMOVE(entry1, entries);
                                                free(entry1);
                                        } else if (nread < 0) {
                                                /* Fatal TLS error */
                                                fprintf(stderr, "%s:%d Error reading from client (TLS)\n", __FILE__, __LINE__);

                                                SSL_shutdown(entry1->ssl);
                                                SSL_free(entry1->ssl);
                                                close(entry1->socketfd);

                                                LIST_REMOVE(entry1, entries);
                                                free(entry1);
                                        } else {
                                                /* nread > 0: normal case */
                                                if (nread < MAX) {
                                                        buf[nread] = '\0';
                                                } else {
                                                        buf[MAX - 1] = '\0';
                                                }

                                                char command[32], payload[92];
                                                if (sscanf(buf, "%31[^:]:%91[^\n]%*[^\n]", command, payload) == 2) {

                                                        if (strncmp(command, "USERNAME", 8) == 0) {
                                                                if (entry1->username[0] != '\0') {
                                                                        tls_write_safe(entry1->ssl,
                                                                                       "ERROR: Already registered.\n",
                                                                                       strlen("ERROR: Already registered.\n"));
                                                                }
                                                                else if (username_exists(payload)) {
                                                                        tls_write_safe(entry1->ssl,
                                                                                       "ERROR: Username already taken.\n",
                                                                                       strlen("ERROR: Username already taken.\n"));
                                                                        SSL_shutdown(entry1->ssl);
                                                                        SSL_free(entry1->ssl);
                                                                        close(entry1->socketfd);
                                                                        LIST_REMOVE(entry1, entries);
                                                                        free(entry1);
                                                                }
                                                                else {
                                                                        snprintf(entry1->username, sizeof(entry1->username), "%.30s", payload);
                                                                        char msg[MAX];

                                                                        int count = 0;
                                                                        snprintf(msg, MAX, "%s has joined the chat.\n", entry1->username);
                                                                        struct client *other;
                                                                        LIST_FOREACH(other, &clients, entries) {
                                                                                if (other != entry1 && other->username[0] != '\0') {
                                                                                        tls_write_safe(other->ssl, msg, strnlen(msg, MAX));
                                                                                        count++;
                                                                                }
                                                                        }

                                                                        if (!count) {
                                                                                snprintf(msg, MAX, "Welcome %s! You are the only one here.\n", entry1->username);
                                                                        } else {
                                                                                snprintf(msg, MAX, "Welcome %s! There are %d other users here.\n",
                                                                                         entry1->username, count);
                                                                        }
                                                                        tls_write_safe(entry1->ssl, msg, strnlen(msg, MAX));
                                                                }
                                                        }
                                                        else if (strncmp(command, "MSG", 3) == 0) {
                                                                if (entry1->username[0] == '\0') {
                                                                        tls_write_safe(entry1->ssl,
                                                                                       "ERROR: Must register username first.\n",
                                                                                       strlen("ERROR: Must register username first.\n"));
                                                                } else {
                                                                        char msg[MAX];
                                                                        snprintf(msg, MAX, "%.30s: %.60s\n", entry1->username, payload);
                                                                        struct client *other;
                                                                        LIST_FOREACH(other, &clients, entries) {
                                                                                if (other != entry1 && other->username[0] != '\0') {
                                                                                        tls_write_safe(other->ssl, msg, strnlen(msg, MAX));
                                                                                }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (ready < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                perror("select error");
                break;
            }
        }
        /* ready == 0 should not happen (no timeout), ignore */
    }

    close(sockfd);
    SSL_shutdown(dir_ssl);
    SSL_free(dir_ssl);
    close(dir_sockfd);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(dir_ctx);
    EVP_cleanup();

    return EXIT_SUCCESS;
}


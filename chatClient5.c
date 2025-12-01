#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "inet.h"
#include "common.h"

static void init_openssl(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static SSL_CTX *init_client_ssl_context(const char *ca_file)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        fprintf(stderr, "Failed to set minimum TLS version\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) {
        fprintf(stderr, "Could not load CA file %s\n", ca_file);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* We require the peer to have a cert signed by our CA */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

void normalize_topic_name(char *s)
{
    for (int i = 0; s[i]; i++) {
        if (s[i] == '_')
            s[i] = ' ';
    }
}

static int verify_expected_subject(SSL *ssl, const char *expected_cn)
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
    strncpy(cn, (const char *)ASN1_STRING_get0_data(data), sizeof(cn) - 1);

    X509_free(cert);

    if (strcmp(cn, expected_cn) != 0) {
        fprintf(stderr, "Certificate CN mismatch: expected '%s', got '%s'\n",
                expected_cn, cn);
        return 0;
    }

    return 1;
}

static int tls_read_safe(SSL *ssl, char *buf, int size)
{
    int r = SSL_read(ssl, buf, size);

    if (r > 0) return r;

    int err = SSL_get_error(ssl, r);

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return -2;   /* not fatal, try later */

    if (err == SSL_ERROR_ZERO_RETURN)
        return 0;    /* clean shutdown */

    /* Fatal TLS error */
    fprintf(stderr, "TLS read error: %d\n", err);
    ERR_print_errors_fp(stderr);
    return -1;
}

static int tls_write_safe(SSL *ssl, const char *buf, int len)
{
    int r = SSL_write(ssl, buf, len);

    if (r > 0) return r;

    int err = SSL_get_error(ssl, r);

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return -2;   /* try again later */

    /* Fatal TLS error */
    fprintf(stderr, "TLS write error: %d\n", err);
    ERR_print_errors_fp(stderr);
    return -1;
}

int main()
{
	char s[MAX] = {'\0'};
	int dir_sockfd = -1;
	int	sockfd = -1;
	struct sockaddr_in serv_addr;
	fd_set readset;
	char username[31] = {'\0'};
	int response = 0;

	SSL_CTX *client_ctx = NULL;
    SSL     *dir_ssl    = NULL;
    SSL     *chat_ssl   = NULL;

	/* Initialize OpenSSL and client TLS */
	init_openssl();
    client_ctx = init_client_ssl_context("ca-cert.pem");


	//directory server code
	/* Set up the address of the server to be contacted. */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family			= AF_INET;
	serv_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Create a socket (an endpoint for communication). */
	if ((dir_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the directory server. */
	if (connect(dir_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("client: can't connect to server");
		return EXIT_FAILURE;
	}

	dir_ssl = SSL_new(client_ctx);
    if (!dir_ssl) {
        fprintf(stderr, "Failed to create SSL object for directory connection\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    SSL_set_fd(dir_ssl, dir_sockfd);

    if (SSL_connect(dir_ssl) <= 0) {
        fprintf(stderr, "TLS handshake with Directory Server failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Verify Directory Server certificate CN = "Directory Server" */
    if (!verify_expected_subject(dir_ssl, "Directory Server")) {
        fprintf(stderr, "Directory Server certificate CN mismatch\n");
        goto cleanup;
    }

    /* Send CHAT request (over TLS) to list active rooms */
    const char *chat_req = "CHAT:here I am!:0\n";
    if (tls_write_safe(dir_ssl, chat_req, (int)strnlen(chat_req, MAX)) <= 0) {
        fprintf(stderr, "Failed to send CHAT request to Directory Server\n");
        goto cleanup;
    }

	int chat_directory_response = 0;
	while(!chat_directory_response){ 

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(dir_sockfd, &readset);

		if (select(dir_sockfd+1, &readset, NULL, NULL, NULL) > 0){

			/* Check whether there's a message from the directory server to read */
			if (FD_ISSET(dir_sockfd, &readset)) {
				int nread = tls_read_safe(dir_ssl, s, MAX - 1);
				if (nread < 0) {
					fprintf(stderr, "Error. Try again\n");
					close(dir_sockfd);
					return 0;
				}
				else if (nread == 0) {
					fprintf(stderr, "Server connection closed\n");
					chat_directory_response = 1;
					close(dir_sockfd);
				}	
				else{
					s[nread] = '\0';  // Null-terminate the string
					printf("%s", s);  // Display the message from the server
					fflush(stdout);
					chat_directory_response = 1;
					close(dir_sockfd);
				}
			}
		}
	}

	SSL_shutdown(dir_ssl);
    SSL_free(dir_ssl);
    dir_ssl = NULL;
    close(dir_sockfd);
    dir_sockfd = -1;


	printf("Enter ServerName,ServerIP,ServerPort: ");
	char input[MAX];

	char server_name[MAX] = {'\0'};
    char server_ip[MAX]   = {'\0'};
    int  server_port     = 0;

	if (fgets(input, sizeof(input), stdin) != NULL) {
		//size_t in_len = strnlen(input, MAX);
		//if (in_len > 0 && input[in_len - 1] == '\n') {
		//	input[in_len - 1] = '\0';
		//}
		if (sscanf(input, " %[^,] , %[^,] , %d", server_name, server_ip, &server_port) == 3) {
			printf("Connecting to chat server '%s' at %s,%d\n", server_name, server_ip, server_port);
		} else {
			fprintf(stderr, "Invalid input format. Expected: ServerName,ServerIP,ServerPort\n");
			return EXIT_FAILURE;
		}
	} else {
		fprintf(stderr, "Error reading input\n");
		return EXIT_FAILURE;
	}

	struct sockaddr_in chat_serv_addr;
	memset((char *) &chat_serv_addr, 0, sizeof(chat_serv_addr));
	chat_serv_addr.sin_family			= AF_INET;
	chat_serv_addr.sin_addr.s_addr	= inet_addr(server_ip);	/* hard-coded in inet.h */
	chat_serv_addr.sin_port			= htons(server_port);			/* user input */

	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the chat server. */
	if (connect(sockfd, (struct sockaddr *) &chat_serv_addr, sizeof(chat_serv_addr)) < 0) {
		perror("client: can't connect to server");
		return EXIT_FAILURE;
	}

	chat_ssl = SSL_new(client_ctx);
    if (!chat_ssl) {
        fprintf(stderr, "Failed to create SSL object for chat server\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    SSL_set_fd(chat_ssl, sockfd);

    if (SSL_connect(chat_ssl) <= 0) {
        fprintf(stderr, "TLS handshake with Chat Server failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

	normalize_topic_name(server_name);


    if (!verify_expected_subject(chat_ssl, server_name)) {
        fprintf(stderr, "Chat Server certificate CN mismatch\n");
        goto cleanup;
    }




	while(!response){
		printf("Enter your username: ");
		char input[MAX];
		if (fgets(input, sizeof(input), stdin) != NULL) {

			size_t in_len = strnlen(input, MAX);
			if (in_len > 0 && input[in_len - 1] == '\n') {
				input[in_len - 1] = '\0';
			}

			// Take only the first word, ignore rest
			if (sscanf(input, "%s", username) == 1) {
				if (strnlen(username, MAX) < 1 || strnlen(username, MAX) > 31) {
					fprintf(stderr, "Username must be between 1 and %d characters\n", 31);
				} else {
					response = 1; // valid username
					fprintf(stderr,"Username set to: %s\n", username); //DEBUG
					char buf[MAX];
					snprintf(buf, MAX, "USERNAME:%s\n", username);
						
					int w = tls_write_safe(chat_ssl, buf,
                                           (int)strnlen(buf, MAX));
                    if (w <= 0) {
                        fprintf(stderr,
                                "client: failed to send username to chat server\n");
                        goto cleanup;
                    }
				}

			} else {
				fprintf(stderr, "Invalid input, please try again.\n");
			}
		}
	}


	for(;;) {

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);

		if (select(sockfd+1, &readset, NULL, NULL, NULL) > 0)
		{
			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				char input[MAX - strnlen("MSG:\n", MAX)];
				if (fgets(input, sizeof(input), stdin) != NULL) {

					/* Send the user's message to the server */
					char buf1[MAX];
					snprintf(buf1, MAX, "MSG:%s\n", input);
					int w = tls_write_safe(chat_ssl, buf1,
                                       (int)strnlen(buf1, MAX));
					if (w <= 0) {
						fprintf(stderr, "Error sending message to chat server\n");
						goto cleanup;
					}
				} else {
					fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__); //DEBUG
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
				int nread = tls_read_safe(chat_ssl, s, MAX - 1);
				if (nread < 0) {
					fprintf(stderr, "Try again\n");
					close(sockfd);
					return 0;
				}
				if (nread == 0) {
					fprintf(stderr, "Server connection closed\n");
					close(sockfd);
					return 0;
				}	
				else{
					if (nread < MAX){
						s[nread] = '\0';  // Null-terminate the string
					} else {
						s[MAX - 1] = '\0'; // Ensure null-termination
					}
        			printf("%s", s);  // Display the message from the server
        			fflush(stdout);
				}
			}
		}
	}
	close(sockfd);

	cleanup:
		if (chat_ssl) {
			SSL_shutdown(chat_ssl);
			SSL_free(chat_ssl);
			chat_ssl = NULL;
		}
		if (sockfd >= 0) {
			close(sockfd);
			sockfd = -1;
		}

		if (dir_ssl) {
			SSL_shutdown(dir_ssl);
			SSL_free(dir_ssl);
			dir_ssl = NULL;
		}
		if (dir_sockfd >= 0) {
			close(dir_sockfd);
			dir_sockfd = -1;
		}

		if (client_ctx) {
			SSL_CTX_free(client_ctx);
			client_ctx = NULL;
		}




	// return or exit(0) is implied; no need to do anything because main() ends
	// testing for the git hub make sure it works
}

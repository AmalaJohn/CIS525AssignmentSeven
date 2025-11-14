#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"

int main()
{
	char s[MAX] = {'\0'};
	int dir_sockfd;
	int	sockfd;
	struct sockaddr_in serv_addr;
	fd_set readset;
	char username[31] = {'\0'};
	int response = 0;

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

	write(dir_sockfd, "CHAT:here I am!:0\n", strnlen("CHAT:here I am!:0\n", MAX));

	int chat_directory_response = 0;
	while(!chat_directory_response){ 

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(dir_sockfd, &readset);

		if (select(dir_sockfd+1, &readset, NULL, NULL, NULL) > 0){

			/* Check whether there's a message from the directory server to read */
			if (FD_ISSET(dir_sockfd, &readset)) {
				ssize_t nread = read(dir_sockfd, s, MAX);
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

	printf("Enter ServerIP,ServerPort: ");
	char input[MAX];

	char server_ip[MAX];
	int server_port;

	if (fgets(input, sizeof(input), stdin) != NULL) {
		//size_t in_len = strnlen(input, MAX);
		//if (in_len > 0 && input[in_len - 1] == '\n') {
		//	input[in_len - 1] = '\0';
		//}
		if (sscanf(input, " %[^,] , %d", server_ip, &server_port) == 2) {
			printf("Connecting to chat server at %s,%d\n", server_ip, server_port);
		} else {
			fprintf(stderr, "Invalid input format. Expected: ServerIP,ServerPort\n");
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
						

					if (write(sockfd, buf, strnlen(buf, MAX)) < 0) {
						perror("client: failed to send username");
						return EXIT_FAILURE;
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
					write(sockfd, buf1, MAX);
				} else {
					fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__); //DEBUG
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
				ssize_t nread = read(sockfd, s, MAX);
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
	// return or exit(0) is implied; no need to do anything because main() ends
	// testing for the git hub make sure it works
}

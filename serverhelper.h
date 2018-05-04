#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>  
#include <ctype.h>

int atoport( char *service, char *proto );
struct in_addr *atoaddr( char *address);
int get_connection( int socket_type, u_short port, int *listener );
int make_connection( char *service, int type, char *netaddress );
int sock_read( int sockfd, char *buf, size_t count );
int sock_write( int sockfd, const char *buf, size_t count );
int sock_gets( int sockfd, char *str, size_t count );
int sock_puts( int sockfd, const char *str );
void ignore_pipe(void);

int sock;            /* The socket file descriptor for our "listening"
                   	socket */
int connectlist[5];  /* Array of connected sockets so we know who
	 		we are talking to */
fd_set socks;        /* Socket file descriptors we want to wake
			up for, using select() */
int highsock;	     /* Highest #'d file descriptor, needed for select() */

void setnonblocking(int sock){
	int opts;

	opts = fcntl(sock,F_GETFL);
	if (opts < 0) {
		perror("fcntl(F_GETFL)");
		exit(EXIT_FAILURE);
	}
	opts = (opts | O_NONBLOCK);
	if (fcntl(sock,F_SETFL,opts) < 0) {
		perror("fcntl(F_SETFL)");
		exit(EXIT_FAILURE);
	}
}

void build_select_list() {
	int listnum;	     /* Current item in connectlist for for loops */

	/* First put together fd_set for select(), which will
	   consist of the sock veriable in case a new connection
	   is coming in, plus all the sockets we have already
	   accepted. */
	
	
	/* FD_ZERO() clears out the fd_set called socks, so that
		it doesn't contain any file descriptors. */
	
	FD_ZERO(&socks);
	
	/* FD_SET() adds the file descriptor "sock" to the fd_set,
		so that select() will return if a connection comes in
		on that socket (which means you have to do accept(), etc. */
	
	FD_SET(sock,&socks);
	
	/* Loops through all the possible connections and adds
		those sockets to the fd_set */
	
	for (listnum = 0; listnum < 5; listnum++) {
		if (connectlist[listnum] != 0) {
			FD_SET(connectlist[listnum],&socks);
			if (connectlist[listnum] > highsock)
				highsock = connectlist[listnum];
		}
	}
}

void handle_new_connection() {
	int listnum;	     /* Current item in connectlist for for loops */
	int connection; /* Socket file descriptor for incoming connections */

	/* We have a new connection coming in!  We'll
	try to find a spot for it in connectlist. */
	connection = accept(sock, NULL, NULL);
	if (connection < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}
	setnonblocking(connection);
	for (listnum = 0; (listnum < 5) && (connection != -1); listnum ++)
		if (connectlist[listnum] == 0) {
			printf("\nConnection accepted:   FD=%d; Slot=%d\n",
				connection,listnum);
			connectlist[listnum] = connection;
			connection = -1;
		}
	if (connection != -1) {
		/* No room left in the queue! */
		printf("\nNo room left for new client.\n");
		sock_puts(connection,"Sorry, this server is too busy. Try again later!\r\n");
		close(connection);
	}
}

void deal_with_data(
	int listnum			/* Current item in connectlist for for loops */
	) {
	char buffer[80];     /* Buffer for socket reads */
	char *cur_char;      /* Used in processing buffer */

	if (sock_gets(connectlist[listnum],buffer,80) < 0) {
		/* Connection closed, close this end
		   and free up entry in connectlist */
		printf("\nConnection lost: FD=%d;  Slot=%d\n",
			connectlist[listnum],listnum);
		close(connectlist[listnum]);
		connectlist[listnum] = 0;
	} else {
		/* We got some data, so upper case it
		   and send it back. */
		printf("\nReceived: %s; ",buffer);
		cur_char = buffer;
		while (cur_char[0] != 0) {
			cur_char[0] = toupper(cur_char[0]);
			cur_char++;
		}
		sock_puts(connectlist[listnum],buffer);
		sock_puts(connectlist[listnum],"\n");
		printf("responded: %s\n",buffer);
	}
}

void read_socks() {
	int listnum;	     /* Current item in connectlist for for loops */

	/* OK, now socks will be set with whatever socket(s)
	   are ready for reading.  Lets first check our
	   "listening" socket, and then check the sockets
	   in connectlist. */
	
	/* If a client is trying to connect() to our listening
		socket, select() will consider that as the socket
		being 'readable'. Thus, if the listening socket is
		part of the fd_set, we need to accept a new connection. */
	
	if (FD_ISSET(sock,&socks))
		handle_new_connection();
	/* Now check connectlist for available data */
	
	/* Run through our sockets and check to see if anything
		happened with them, if so 'service' them. */
	
	for (listnum = 0; listnum < 5; listnum++) {
		if (FD_ISSET(connectlist[listnum],&socks))
			deal_with_data(listnum);
	} /* for (all entries in queue) */
}
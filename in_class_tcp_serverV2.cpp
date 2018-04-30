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
#include </Users/jasha/Desktop/serverhelper.h>


/**
 * Print IP:PORT of client address to stdout.
 *
 * @param client_address
 */
void print_address_details(sockaddr_in *client_address) {
  static char addrbuf[INET_ADDRSTRLEN];
  const char *ret;
  ret = inet_ntop(AF_INET, &client_address->sin_addr, addrbuf,
                  INET_ADDRSTRLEN);

  if (ret != NULL) {
    std::cout << addrbuf << ":" << ntohs(client_address->sin_port);
  }

  return;
}
/**
 *
 * TCP server example. Reads in IP PORT
 * from the command line, and accepts connections via TCP
 * on IP:PORT.
 *
 * e.g., ./tcpserver 127.0.0.1 8888
 *
 * @param argc count of arguments on the command line
 * @param argv array of command line arguments
 * @return 0 on success, non-zero if an error occurred
 */
int main(int argc, char *argv[]) {
  // Alias for argv[1] for convenience
  char *ip_string;
  // Alias for argv[2] for convenience
  char *port_string;

  // Port to send TCP data to. Need to convert from command line string to a number
  unsigned int port;
  // The socket used to send data
  int tcp_socket;
  // Variable used to check return codes from various functions
  int ret;

  int client_socket;

  struct sockaddr_in client_address;
  socklen_t client_address_len;

  struct addrinfo hints;
  struct addrinfo *results;
  struct addrinfo *results_it;

  // Note: this needs to be 3, because the program name counts as an argument!
  if (argc < 3) {
    std::cerr << "Please specify HOSTNAME PORT as first two arguments." << std::endl;
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];

  // Create the TCP socket.
  // AF_INET is the address family used for IPv4 addresses
  // SOCK_STREAM indicates creation of a TCP socket
  tcp_socket = socket(AF_INET, SOCK_STREAM, 0);

  // Make sure socket was created successfully, or exit.
  if (tcp_socket == -1) {
    std::cerr << "Failed to create tcp socket!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    return 1;
  }
int flags = fcntl(tcp_socket, F_GETFL); 
  if (flags == -1) { 
  perror("get flags using fcntl()"); 
  exit(EXIT_FAILURE); 
  } 
  
  int res = fcntl(tcp_socket, F_SETFL, flags | O_NONBLOCK);
   if (flags == -1) {   
     perror(" set O_NONBLOCK using fcntl()");  
      exit(EXIT_FAILURE); 
      }

  struct timeval timeout;
  timeout.tv_sec = 2;
  timeout.tv_usec = 0; 


  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_family = AF_INET;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = SOCK_STREAM;
  // Instead of using inet_pton, use getaddrinfo to convert.
  ret = getaddrinfo(ip_string, port_string, &hints, &results);

  if (ret != 0) {
    std::cerr << "Getaddrinfo failed with error " << ret << std::endl;
    perror("getaddrinfo");
    return 1;
  }

  // Check we have at least one result
  results_it = results;

  ret = -1;
  while (results_it != NULL) {
    std::cout << "Trying to connect to something?" << std::endl;
    ret = bind(tcp_socket, results_it->ai_addr, results_it->ai_addrlen);
    //ret = connect(tcp_socket, results_it->ai_addr, results_it->ai_addrlen);
    if (ret == 0) {
      break;
    }
    perror("bind");
    results_it = results_it->ai_next;
  }

  // Whatever happened, we need to free the address list.
  freeaddrinfo(results);

  // Check if connecting succeeded at all
  if (ret != 0) {
    std::cout << "Failed to bind to any addresses!" << std::endl;
    return 1;
  }

  // Listen on the tcp socket
  ret = listen(tcp_socket, 50);

  // Check if connecting succeeded at all
  if (ret != 0) {
    std::cout << "Failed to listen!" << std::endl;
    close(tcp_socket);
    perror("listen");
    return 1;
  }

  client_address_len = sizeof(struct sockaddr_in);
  client_socket = accept(tcp_socket, (struct sockaddr *)&client_address, &client_address_len);

  std::cout << "Accepted connection from : ";
  print_address_details(&client_address);
  std::cout << "\n";

#define RECEIVE_BUF_SIZE 2048
  char recv_buf[RECEIVE_BUF_SIZE];
  ret = recv(client_socket, recv_buf, RECEIVE_BUF_SIZE - 1, 0);
  // Check if send worked, clean up and exit if not.
  if (ret == -1) {
    std::cerr << "Failed to receive data!" << std::endl;
    perror("recv");
    std::cerr << strerror(errno) << std::endl;
    close(client_socket);
    close(tcp_socket);
    return 1;
  }

  /*
  Tried using the slides to do something but quickly got confused so looked at the other examples
  fd_set masterset; 
  fd_set readset; 
  fd_set writeset; 
  fd_set exceptset; 
  // zero them out 
  FD_ZERO(&masterset); 
  FD_ZERO(&readset); 
  FD_ZERO(&writeset); 
  FD_ZERO(&exceptset); 
  // now we set each socket in the fd_set  
  // we’re interested in 
  FD_SET(tcp_socket, &masterset); 
  FD_SET(tcp_socket, &readset); 
  FD_SET(tcp_socket, &writeset); 
  FD_SET(tcp_socket, &exceptset);

  res = select(maxfd+1, &readset, &writeset, &exceptset, &timeout); 
  if (FD_ISSET(tcp_socket, &readset)) {   
    // the socket has data and can be processed 
    } if (FD_ISSET(tcp_socket, &writeset)) {  
       // the socket is ready to be written
        } 
        
        readset = masterset; 
      



  // Instead looked at the examples and it made more sense, might be able able to translate it  ¯\_(ツ)_/¯
  int reuse_addr;
  sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	// So that we can re-bind to it without TIME_WAIT problems //
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

	// Set socket to non-blocking with our setnonblocking routine //
	setnonblocking(sock);
  std::cout << "Received " << ret << " bytes " << std::endl;
  recv_buf[ret] = '\0';
  std::cout << recv_buf << std::endl;

  int readsocks;
  /* Set up queue for incoming connections.
	listen(sock,5);
  highsock = sock;
	memset((char *) &connectlist, 0, sizeof(connectlist));

	while (1) { /* Main server loop - forever 
		build_select_list();
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		
		/* The first argument to select is the highest file
			descriptor value plus 1. In most cases, you can
			just pass FD_SETSIZE and you'll be fine. */
			
		/* The second argument to select() is the address of
			the fd_set that contains sockets we're waiting
			to be readable (including the listening socket). */
			
		/* The third parameter is an fd_set that you want to
			know if you can write on -- this example doesn't
			use it, so it passes 0, or NULL. The fourth parameter
			is sockets you're waiting for out-of-band data for,
			which usually, you're not. */
		
		/* The last parameter to select() is a time-out of how
			long select() should block. If you want to wait forever
			until something happens on a socket, you'll probably
			want to pass NULL. 
		
		readsocks = select(highsock+1, &socks, (fd_set *) 0, 
		  (fd_set *) 0, &timeout);
		
		/* select() returns the number of sockets that had
			things going on with them -- i.e. they're readable. */
			
		/* Once select() returns, the original fd_set has been
			modified so it now reflects the state of why select()
			woke up. i.e. If file descriptor 4 was originally in
			the fd_set, and then it became readable, the fd_set
			contains file descriptor 4 in it. 
		
		if (readsocks < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		}
		if (readsocks == 0) {
			/* Nothing ready to read, just show that
			   we're alive 
			printf(".");
			fflush(stdout);
		} else
			read_socks();
	} /* while(1) */
  ret = send(client_socket, recv_buf, ret, 0);

  close(client_socket);
  close(tcp_socket);
  return 0;
}


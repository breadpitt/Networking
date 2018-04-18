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

#include "udp_chat.h"

// #include "udpserver.h"
std::string get_nickname() {
  std::string nickname;
  std::cout << "Enter chat nickname: ";
  std::getline(std::cin, nickname);
  return nickname;
}

std::string get_message() {
  std::string nickname;
  std::cout << "Enter chat message to send, or quit to quit: ";
  std::getline(std::cin, nickname);
  return nickname;
}

/**
 *
 * UDP chat client example. Reads in IP PORT
 * from the command line, and sends DATA via UDP to IP:PORT.
 *
 * e.g., ./udpchatclient 127.0.0.1 8888
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

  // Port to send UDP data to. Need to convert from command line string to a number
  unsigned int port;
  // The socket used to send UDP data on
  int udp_socket;
  // Variable used to check return codes from various functions
  int ret;
  // IPv4 structure representing and IP address and port of the destination
  struct sockaddr_in dest_addr;
  std::string nickname;
  char send_buffer[2048];

  // Set dest_addr to all zeroes, just to make sure it's not filled with junk
  // Note we could also make it a static variable, which will be zeroed before execution
  memset(&dest_addr, 0, sizeof(struct sockaddr_in));

  // Note: this needs to be 3, because the program name counts as an argument!
  if (argc < 3) {
    std::cerr << "Please specify IP PORT as first two arguments." << std::endl;
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];

  // Create the UDP socket.
  // AF_INET is the address family used for IPv4 addresses
  // SOCK_DGRAM indicates creation of a UDP socket
  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

  // Make sure socket was created successfully, or exit.
  if (udp_socket == -1) {
    std::cerr << "Failed to create udp socket!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    return 1;
  }

  // inet_pton converts an ip address string (e.g., 1.2.3.4) into the 4 byte
  // equivalent required for using the address in code.
  // Note that because dest_addr is a sockaddr_in (again, IPv4) the 'sin_addr'
  // member of the struct is used for the IP
  ret = inet_pton(AF_INET, ip_string, (void *)&dest_addr.sin_addr);

  // Check whether the specified IP was parsed properly. If not, exit.
  if (ret == -1) {
    std::cerr << "Failed to parse IPv4 address!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  // Convert the port string into an unsigned integer.
  ret = sscanf(port_string, "%u", &port);
  // sscanf is called with one argument to convert, so the result should be 1
  // If not, exit.
  if (ret != 1) {
    std::cerr << "Failed to parse port!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  // Set the address family to AF_INET (IPv4)
  dest_addr.sin_family = AF_INET;
  // Set the destination port. Use htons (host to network short)
  // to ensure that the port is in big endian format
  dest_addr.sin_port = htons(port);

// Send connect message
  struct ChatClientMessage client_connect;
  client_connect.type = htons(CLIENT_CONNECT);
  client_connect.data_length = 0;

  ret = sendto(udp_socket, &client_connect, sizeof(client_connect), 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));
  if (ret == -1){
    std::cerr << "Failed to send connect request!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
  }

  std::cout << "CONNECT: NUMBER OF BYTES SENT" << ret << std::endl;

  nickname = get_nickname();

  // Send nickname message
  struct ChatClientMessage send_nickname;
  send_nickname.type = htons(CLIENT_SET_NICKNAME);
  send_nickname.data_length = htons(sizeof(nickname));

  uint16_t set_nickname_buf[sizeof(nickname) + sizeof(ChatClientMessage)];
  memcpy(set_nickname_buf, &send_nickname, sizeof(send_nickname));
  ret = sendto(udp_socket, &send_nickname, sizeof(send_nickname), 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));
  
    std::cout << "NICKNAME STRUCT: NUMBER OF BYTES SENT" << ret << std::endl;

  ret = sendto(udp_socket, &nickname, sizeof(nickname), 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));
    
    std::cout << "NICKNAME: NUMBER OF BYTES SENT" << ret << std::endl;

  if (ret == -1){
    std::cerr << "Failed to set nickname!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
  }
  
    struct ChatClientMessage send_client_message;
    
  // Note 3: the return value of sendto is the number of bytes sent
 
  std::string next_message;
  next_message = get_message();

  while (next_message != "quit") {
    send_client_message.type = htons(CLIENT_SEND_MESSAGE);
    send_client_message.data_length = htons(next_message.length());

    memcpy(send_buffer, &send_client_message, sizeof(send_client_message));
    memcpy(&send_buffer[sizeof(send_client_message)], next_message.c_str(), strlen(next_message.c_str())); // Use strlen here to not include null terminator
    ret = sendto(udp_socket, &send_buffer, sizeof(send_buffer), 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));
    std::cout << "MESSAGE: NUMBER OF BYTES " << ret << std::endl;

    if (ret == -1){
      std::cerr << "Message failed to send!" << std::endl;
      std::cerr << strerror(errno) << std::endl;
      }
    next_message = get_message();
  }

  // Send client disconnect message
  struct ChatClientMessage client_disconnect;
  client_disconnect.type = CLIENT_DISCONNECT;
  client_disconnect.data_length = 0;
  ret = sendto(udp_socket, &client_disconnect, sizeof(client_disconnect), 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));
  std::cout << "DISCONNECT: NUMBER OF BYTES " << ret << std::endl;

  if (ret == -1){
    std::cerr << "Failed to send disconnect request!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
  }
  close(udp_socket);
  return 0;
}

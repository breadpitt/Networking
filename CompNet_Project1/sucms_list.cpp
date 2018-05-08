
 /**
 * James Shannon
 * Project 1
 */
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <vector>
#include <fstream>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "SUCMS.h"
#include <cerrno>
#include <openssl/md5.h>

using std::cin;
using std::cout;
using std::cerr;
using std::getline;
using std::istringstream;
using std::string;
using std::vector;
using std::ifstream;

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
  struct sockaddr_in server_addr;
  // IPv4 structure representing the IP address and port of responding server
  //struct sockaddr_in server_addr;
  struct sockaddr from;
  // Holds the length of the server ip address
  socklen_t from_addr_length;
  from_addr_length = sizeof(struct sockaddr);
  // Variable used to store a user's name
  string username;
  // Variable used to store a user's password
  string password;
  // Variable used to store a user's permissions
  string permissions;

  struct addrinfo hints;
  struct addrinfo *results;

  

  // Set server_addr to all zeroes, just to make sure it's not filled with junk
  memset(&server_addr, 0, sizeof(struct sockaddr_in));

  // Note: this needs to be 4, because the program name counts as an argument!
  if (argc < 3) { // change back to 4 after hard code testing
    std::cerr << "Please specify IP PORT FILE as first three arguments." << std::endl; 
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];
  //string fileName(argv[3]);


  
    std::cout << "Please enter your username: \n";
    std::cin >> username;
    std::cout << "Please enter your password: \n";
    std::cin >> password;
    //permissions = "rwd";
  
  
  // Create the UDP socket. AF_INET used for IPv4 addresses. SOCK_DGRAM indicates creation of a UDP socket
  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

  if (udp_socket == -1) {
    std::cerr << "Failed to create udp socket!" << std::endl;
    return 1;
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_family = AF_INET;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = SOCK_DGRAM;
  char hostname[NI_MAXHOST];

  ret = getaddrinfo(ip_string, port_string, &hints, &results);
  if (ret != 0) {
    std::cerr << "Getaddrinfo failed with error " << ret << std::endl;
    perror("getaddrinfo");
    return 1;
  }

  if (results != NULL){
    std::cout << "Trying to connect \n";
    ret = connect(udp_socket, results->ai_addr, results->ai_addrlen);
      if (ret != 0){
        freeaddrinfo(results);
        std::cout << "Failure to connect to " << ip_string << "\n";
        return 1;
      }
  }
  std::cout << "Connection Successful\nSending Data\n";
  //getnameinfo(results->ai_addr, results->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0);
  //printf("hostname: %s\n", hostname);
  freeaddrinfo(results);
  /*
  // inet_pton converts an ip addr str into the required format
  // Note that because server_addr is a sockaddr_in (again, IPv4) the 'sin_addr'
  // member of the struct is used for the IP
  ret = inet_pton(AF_INET, ip_string, (void *)&server_addr.sin_addr);

  // Check whether the specified IP was parsed properly. If not, exit.
  if (ret == -1) {
    std::cerr << "Failed to parse IPv4 address!" << std::endl;
    close(udp_socket);
    return 1;
  }
  
  // Convert the port string into an unsigned integer.
  ret = sscanf(port_string, "%u", &port);
  if (ret != 1) {
    std::cerr << "Failed to parse port!" << std::endl;
    close(udp_socket);
    return 1;
  }

  // Set the address family to AF_INET (IPv4)
  server_addr.sin_family = AF_INET;
  // Set the destination port. Use htons (host to network short)
  // to ensure that the port is in big endian format
  server_addr.sin_port = htons(port);
  */

CommandMessage initList; // Create the command message
  initList.username_len = strlen(username.c_str());
  initList.command = 80; // 80 is LIST
  
  MD5((unsigned char *)password.c_str(), 
          strlen(password.c_str()), initList.password_hash); 
   

  SUCMSHeader initHeader;
  initHeader.sucms_msg_type = 50; // Command type
  initHeader.sucms_msg_length = sizeof(initList) + initList.username_len; 
  
  int initHeaderSize = sizeof(initHeader);
  int initListSize = sizeof(initList);
  
 
  int username_length = strlen(username.c_str());
  //std::cout << "before: " << initHeader.sucms_msg_type << std::endl; -> test htons was working right.. it was
  initHeader.sucms_msg_type = htons(initHeader.sucms_msg_type);
  //std::cout << "after: " << initHeader.sucms_msg_type << std::endl;
   initHeader.sucms_msg_type = ntohs(initHeader.sucms_msg_type);
   // std::cout << "after after: " << initHeader.sucms_msg_type << std::endl;
  initHeader.sucms_msg_length = htons(initHeader.sucms_msg_length);
  initList.username_len = htons(initList.username_len);
  initList.command = htons(initList.command);

  // Create and populate buffer used to send initial message to server
  uint16_t initBuf[sizeof(initHeader) + sizeof(initList) + username_length];
  int initBufSize = sizeof(initList) + sizeof(initHeader) + username_length;
   
  memcpy(initBuf, &initHeader, sizeof(initHeader));
  memcpy(initBuf + sizeof(initHeader), &initList, sizeof(initList));
  memcpy(initBuf + sizeof(initHeader) + sizeof(initList), username.c_str(), strlen(username.c_str()));
  
  // Note 1: we are sending strlen(data_string) + 1 to include the null terminator
  // Note 2: we are casting server_addr to a struct sockaddr because sendto uses the size
  //         and family to determine what type of address it is.
  // Note 3: the return value of sendto is the number of bytes sent
 ret = send(udp_socket, initBuf, sizeof(initBuf), 0);

  // Check if send worked, clean up and exit if not.
  if (ret == -1) {
    std::cerr << "Failed to send data!" << std::endl;
    close(udp_socket);
    return 1;
  }

  std::cout << "Sent " << ret << " bytes out." << std::endl;

  
  uint16_t recv_buf[2048];
  uint16_t messageType, messageLength; // sucms message type and length
  uint16_t commandCode, resultID, messageCount; // command response variables
  uint32_t messageDataSize; // Size of data received by command response
  //int from_addr_length;
  //from_addr_length = sizeof(from); 
  ret = recv(udp_socket, &recv_buf, sizeof(recv_buf) - 1, 0); // Receive up to 2047 bytes of data

  if (ret < 4) {
    std::cerr << "Failed to recvfrom!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }
  recv_buf[ret] = '\0';
  
  std::cout << "Received " << ret << " bytes." << std::endl;
  messageType = ntohs(recv_buf[0]);
  std::cout << "messageType: " << messageType << "\n";
  messageLength = ntohs(recv_buf[1]);
  std::cout << "messageLength: " << messageLength << "\n";
  commandCode = ntohs(recv_buf[2]);
  std::cout << "commandCode: " << commandCode << "\n";
  
  switch(commandCode){
      case 10 : std::cout << "AUTH_OK\n";
        break;
      case 11 : std::cout << "AUTH_FAILED\n";
        break;
      case 12 : std::cout << "ACCESS_DENIED\n";
        break;
      case 13 : std::cout << "NO_SUCH_FILE\n";
        break;
      case 14 : std::cout << "INVALID_RESULT_ID\n";
        break;
      case 15 : std::cout << "INTERNAL_SERVER_ERROR\n";
        break;
      case 16 : std::cout <<  "INVALID_CLIENT_MESSAGE\n";
  }


  resultID = ntohs(recv_buf[3]);

  // 32 bit variable likely got chopped up into two 16 bit slots so we need to cast, shift, and cat in order to get it back into the right format
  messageDataSize = ntohl(recv_buf[4]);
  std::cout << "messageDataSize: " << messageDataSize << "\n";
  messageCount = (ntohs(recv_buf[6])); 
  std::cout << "messageCount: " << messageCount << "\n";






  close(udp_socket);
  return 0;
}
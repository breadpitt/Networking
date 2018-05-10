
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
#include <unistd.h>
#include "SUCMS.h"
#include <cerrno>
#include <openssl/md5.h>
#include <netdb.h>

using std::cin;
using std::cout;
using std::cerr;
using std::getline;
using std::istringstream;
using std::string;
using std::vector;
using std::ifstream;

/**
 *
 * Dead simple UDP client example. Reads in IP PORT DATA
 * from the command line, and sends DATA via UDP to IP:PORT.
 *
 * e.g., ./udpclient 127.0.0.1 8888 this_is_some_data_to_send
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
  //int udp_socket;
  // Variable used to check return codes from various functions
  int ret;
  // IPv4 structure representing and IP address and port of the destination
  //struct sockaddr_in server_addr;
  // IPv4 structure representing the IP address and port of responding server
  //struct sockaddr_in server_addr;
 // struct sockaddr from;
  // Holds the length of the server ip address
  //socklen_t from_addr_length;
  //from_addr_length = sizeof(struct sockaddr);
  // Variable used to store a user's name
  string username;
  // Variable used to store a user's password
  string password;
  // Variable used to store a user's permissions
  string permissions;
   int sockfd;
    int serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
  // Set server_addr to all zeroes, just to make sure it's not filled with junk
  // Note we could also make it a static variable, which will be zeroed before execution
  memset(&serveraddr, 0, sizeof(struct sockaddr_in));

  // Note: this needs to be 4, because the program name counts as an argument!
  if (argc < 3) { // change back to 4 after hard code testing
    std::cerr << "Please specify IP PORT FILE as first three arguments." << std::endl; 
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];

    std::cout << "Please enter your username: \n";
    std::cin >> username;
    std::cout << "Please enter your password: \n";
    std::cin >> password;
  
  // Create the UDP socket. AF_INET used for IPv4 addresses. SOCK_DGRAM indicates creation of a UDP socket
  //udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){ 
        std::cout << "ERROR opening socket\n";
    }
  // Make sure socket was created successfully, or exit.
 // if (udp_socket == -1) {
   // std::cerr << "Failed to create udp socket!" << std::endl;
    //return 1;
  //}
   

  // inet_pton converts an ip addr str into the required format
  // Note that because server_addr is a sockaddr_in (again, IPv4) the 'sin_addr'
  // member of the struct is used for the IP
  //ret = inet_pton(AF_INET, ip_string, (void *)&server_addr.sin_addr);

  // Check whether the specified IP was parsed properly. If not, exit.
  //if (ret == -1) {
   // std::cerr << "Failed to parse IPv4 address!" << std::endl;
    //close(udp_socket);
    //return 1;
  //}

  // Convert the port string into an unsigned integer.
  ret = sscanf(port_string, "%u", &port);
  // sscanf is called with one argument to convert, so the result should be 1
  //if (ret != 1) {
    //std::cerr << "Failed to parse port!" << std::endl;
    //close(udp_socket);
    //return 1;
  //}

  // Set the address family to AF_INET (IPv4)
  //server_addr.sin_family = AF_INET;
  // Set the destination port. Use htons (host to network short)
  // to ensure that the port is in big endian format
  //server_addr.sin_port = htons(port);
  server = gethostbyname(ip_string);
   if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", ip_string);
        exit(0);
    }
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(port);

CommandMessage initList; // Create the command message
  initList.username_len = strlen(username.c_str());
  initList.command = 80; // 80 is LIST
  
  MD5((unsigned char *)password.c_str(), strlen(password.c_str()), initList.password_hash); // strlen won't include \0 iirc
   

  SUCMSHeader initHeader;
  initHeader.sucms_msg_type = 50; // Command type
  initHeader.sucms_msg_length = sizeof(initList) + initList.username_len; // sizeof is the count of all the bytes
  
  uint16_t initHeaderSize = sizeof(initHeader);
  int initListSize = sizeof(initList);
  int initBufSize = sizeof(initList) + sizeof(initHeader) + initList.username_len;
  
  /*
  uint16_t initBuf[initBufSize]; // construct a buffer, add the header to it, then append in the command message and username
  std::vector<uint16_t> initVector;
  initVector.push_back(initHeader.sucms_msg_type);
  initVector.push_back(initHeader.sucms_msg_length);
  initVector.push_back(initList.username_len);
  initVector.push_back(initList.command);
  for (int i = 0; i < sizeof(initList.password_hash); i++){
    initVector.push_back(initList.password_hash[i]);
  }
  std::vector<uint16_t> convertVec(username.begin(), username.end());
  for (int i = 0; i < initList.username_len; i++){
    initVector.push_back(convertVec[i]);
  }
  
  
  for (int i = 0; i <initVector.size(); i++){
    printf(" %u ", (unsigned int)initVector[i] );

  }
  */

  uint16_t initBuf[sizeof(initHeader) + sizeof(initList) + initList.username_len]; 
  memcpy(initBuf, &initHeader, sizeof(initHeader));
  memcpy(initBuf + sizeof(initHeader), &initList, sizeof(initList));
  memcpy(initBuf + sizeof(initHeader) + sizeof(initList), username.c_str, initList.username_len);

  // Send the data to the destination.
  // Note 1: we are sending strlen(data_string) + 1 to include the null terminator
  // Note 2: we are casting server_addr to a struct sockaddr because sendto uses the size
  //         and family to determine what type of address it is.
  // Note 3: the return value of sendto is the number of bytes sent
 //ret = sendto(udp_socket, &initVector[0], sizeof(initVector[0]) * initVector.size(), 0,
   //            (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
   const sockaddr_in SERVERADDR = serveraddr;
  serverlen = sizeof(serveraddr);
  //  ret = sendto(sockfd, initBuf, sizeof(initBuf), 0,  &serveraddr, serverlen);
    
    if (ret <= 0){ 
      std::cout << "ERROR in sendto\n";
      close(sockfd);
    return 1;
    }
   
  // Check if send worked, clean up and exit if not.
 // if (ret == -1) {
   // std::cerr << "Failed to send data!" << std::endl;
    //close(udp_socket);
    //return 1;
  //}

  std::cout << "Sent " << ret << " bytes out." << std::endl;

  // The header & response should only be about 7 uint_16s but I'm adding some buffer to my buffer
  //  just in case I messed up my counting, which is always possible
  uint16_t recv_buf[1024];
  uint16_t messageType, messageLength; // sucms message type and length
  uint16_t commandCode, resultID, messageCount; // command response variables
  uint32_t messageDataSize; // Size of data received by command response
  //int from_addr_length;
  //from_addr_length = sizeof(from); 
  //ret = recvfrom(udp_socket, &recv_buf, sizeof(recv_buf) - 1, 0, &from, &from_addr_length); // Receive up to 1024 bytes of data
  ret = recvfrom(sockfd, recv_buf, sizeof(recv_buf) - 1, 0, (sockaddr *)&serveraddr, (socklen_t *)&serverlen);
  if (ret < 4) {
    std::cerr << "Failed to recvfrom!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(sockfd);
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
  resultID = ntohs(recv_buf[3]);
  // 32 bit variable likely got chopped up into two 16 bit slots so we need to cast, shift, and cat in order to get it back into the right format
  messageDataSize = (ntohs((uint32_t)recv_buf[4]) << 16) | ntohs(recv_buf[5]);
  std::cout << "messageDataSize: " << messageDataSize << "\n";
  messageCount = (ntohs(recv_buf[6])); 
  std::cout << "messageCount: " << messageCount << "\n";




  close(sockfd);
  return 0;
}
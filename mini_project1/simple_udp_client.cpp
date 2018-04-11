/**
 * In-class demonstrated UDP client example. 04-04-2018
 */

#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <stdio.h>
// #include "udpserver.h"
// test

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
struct ServerResponse{
    uint16_t type;
    uint16_t secret;
  };
  unsigned char hexval(unsigned char c)
  {
    if ('0' <= c && c <= '9')
        return c - '0';
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    else abort();
  }
  std::string HEX2STR (std::string str)
{
    std::string tmp;
    const char *c = str.c_str();
    unsigned int x;
    while(*c != 0) {
        sscanf(c, "%2X", &x);
        tmp += x;
        c += 2;
    }
    return tmp;
  }
int main(int argc, char *argv[]) {
  // Alias for argv[1] for convenience
  char *ip_string;
  // Alias for argv[2] for convenience
  char *port_string;
  // Alias for argv[3] for convenience
  char *data_string;
  // Port to send UDP data to. Need to convert from command line string to a number
  unsigned int port;
  // The socket used to send UDP data on
  int udp_socket;
  // Variable used to check return codes from various functions
  int ret;
  // IPv4 structure representing and IP address and port of the destination
  struct sockaddr_in dest_addr;
  // IPv$ structure representing the IP address and port of responding server
  struct sockaddr_in server_addr;
  // Holds the length of the server ip address
  socklen_t server_addr_length;
  // Buffer for the bytes returned from a server
  uint16_t recvfrom_buff[2048];
  // server response structure
  struct ServerResponse server_response;

  memset(&dest_addr, 0, sizeof(struct sockaddr_in));

  if (argc < 4) {
    std::cerr << "Please specify IP PORT DATA as first three arguments." << std::endl;
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];
  data_string = argv[3];

  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

  if (udp_socket == -1) {
    std::cerr << "Failed to create udp socket!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    return 1;
  }


  ret = inet_pton(AF_INET, ip_string, (void *)&dest_addr.sin_addr);
  if (ret == -1) {
    std::cerr << "Failed to parse IPv4 address!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  ret = sscanf(port_string, "%u", &port);
  if (ret != 1) {
    std::cerr << "Failed to parse port!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  ret = sendto(udp_socket, data_string, strlen(data_string) + 1, 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

  if (ret == -1) {
    std::cerr << "Failed to send data!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  std::cout << "Sent " << ret << " bytes out." << std::endl;

  server_addr_length = sizeof(struct sockaddr_in);

  ret = recvfrom(udp_socket, &recvfrom_buff, 2047, 0, (struct sockaddr *)&server_addr, &server_addr_length); // Receive up to 2048 bytes of data

  // If less than 4 bytes were returned then the server struct failed to send or some other error occurred
  if (ret < 4) {
    std::cerr << "Failed to recvfrom!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }
  std::cout << "Received " << ret << " bytes from server \n";


  uint16_t response_type = recvfrom_buff[0]; // ServerResponse.type based on the header file

  enum ResponseType{Echo = 0, Empty = 1,  Error = 2};
  switch(response_type){
    case Empty :
              std::cout << "Received EMPTY response from server." << std::endl;
              break;
    case Echo :
              std::cout << "Received ECHO response from server." << std::endl;
              break;
    case Error :
              std::cout << "Received ERROR response from server." << std::endl;
              break;
    default: std::cout << "Response type error." << std::endl;
              return 1;
  }
  std::cout << "Secret was " << recvfrom_buff[1] << std::endl; // ServerResponse.secret based on header file
  char first_byte;
  char second_byte;
  std::string temp_string;
  std::string string_response;

  int n;
  if (response_type = 0){
    for (int i = 2; i < ret; i++){
      first_byte = (uint8_t)recvfrom_buff[i] >> 8; // Bit shift to get the 'higher' byte
      second_byte = (uint8_t)recvfrom_buff[i] & 0xff; // Use a mask to get 'lower byte'
    //  first_byte = hexval(first_byte);
      //second_byte = hexval(second_byte);
      //first_byte = (first_byte << 4) + first_byte;
      //second_byte = (second_byte << 4) + second_byte;
      string_response += std::to_string(first_byte);
      string_response += std::to_string(second_byte);
      //temp_string += std::to_string(first_byte);
      //temp_string += std::to_string(second_byte);
      //std::string byte = temp_string.substr(i,2);
      //char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
      //string_response.push_back(chr);
    //std::cout << (char)first_byte[0];
    //std::cout << (char)second_byte[0];
    //sprintf(string_response, "%c%c", first_byte[0], second_byte[0]); // += std::to_string((char)first_byte[0]);
    //sprintf(string_response, "%c", second_byte[0]); //string_response += std::to_string((char)second_byte[0]);
    //printf("%c%c", first_byte, second_byte);
  }
   //printf("%s\n", string_response); //std::cout << string_response << std::endl;
  //temp_string = HEX2STR(string_response);
   std::cout << string_response << std::endl;
}


if (response_type = 1){
  for (int i = 2; i < ret; i++){
    first_byte = (uint8_t)recvfrom_buff[i] >> 8; // Bit shift to get the 'higher' byte
    second_byte = (uint8_t)recvfrom_buff[i] & 0xff; // Use a mask to get 'lower byte'

    //first_byte = (first_byte << 4) + first_byte;
  //  second_byte = (second_byte << 4) + second_byte;
    string_response += std::to_string(first_byte);
    string_response += std::to_string(second_byte);
    //temp_string += std::to_string(first_byte);
    //temp_string += std::to_string(second_byte);
    //std::string byte = temp_string.substr(i,2);
    //char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
    //string_response.push_back(chr);
    //std::cout << (char)first_byte[0];
    //std::cout << (char)second_byte[0];
    //sprintf(string_response, "%c%c", first_byte[0], second_byte[0]); // += std::to_string((char)first_byte[0]);
    //sprintf(string_response, "%c", second_byte[0]); //string_response += std::to_string((char)second_byte[0]);
    //printf("%c%c", first_byte, second_byte);
    }
    //printf("%s\n", string_response); //std::cout << string_response << std::endl;
    //std::cout << string_response << std::endl;
  //  temp_string = HEX2STR(string_response);
     std::cout << string_response << std::endl;
  }


  close(udp_socket);
  return 0;
}

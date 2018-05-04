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

  server_addr_length = sizeof(struct sockaddr_in);

  ret = recvfrom(udp_socket, &recvfrom_buff, 2047, 0, (struct sockaddr *)&server_addr, &server_addr_length); // Receive up to 2048 bytes of data

  // If less than 4 bytes were returned then the server struct failed to send
  // the other error codes for recvfrom are less than 4 so it covers those as well
  if (ret < 4) {
    std::cerr << "Failed to recvfrom!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  uint8_t response_type;
  response_type = recvfrom_buff[0] >> 8; // Grab the upper bits (shoulda used ntohs but too late for that now)

  char first_byte;
  char second_byte;
  int counter = 0;
  int buff_counter = 2;
  uint16_t secret;

  secret = ntohs(recvfrom_buff[1]);

  if (response_type == 0){
    std::cout << "Received ECHO response from server. Secret was " << secret << std::endl;
    std::cout << "Echoed string was: ";
    while(counter < ret - 4){
      // note to future james: use ntohs on recvfrom buffer so I don't have to do these
      // litte to big endian shenanigans
     first_byte = recvfrom_buff[buff_counter] & 0xff; // Grab lower byte
      counter++;
      second_byte = recvfrom_buff[buff_counter] >> 8; // Grab upper byte
      counter++;
      buff_counter++;
    printf("%c%c", first_byte, second_byte);
  }
  printf("\n");

}

  else if (response_type == 1){
  std::cout << "Received EMPTY response from server. Secret was " << secret << std::endl;
}

  else if (response_type == 2){
  std::cout << "Received ERROR response from server. Secret was " << secret << std::endl;
  std::cout << "Error string was: ";
  while(counter < ret - 4){
    // note to future james: use ntohs on recvfrom buffer so I don't have to do these
    // litte to big endian shenanigans
   first_byte = recvfrom_buff[buff_counter] & 0xff; // Grab lower byte
   counter++;
    second_byte = recvfrom_buff[buff_counter] >> 8; // Grab upper byte
    counter++;
    buff_counter++;
    printf("%c%c", first_byte, second_byte);
    }
    printf("\n");
  }

  else {
    std::cout << "Received UNKOWN response from server. Secret was " << secret << std::endl;
      if (ret > 4){
        std::cout << "UNKOWN DATA: ";
        while(counter < ret - 4){
          // note to future james: use ntohs on recvfrom buffer so I don't have to do these
          // litte to big endian shenanigans
         first_byte = recvfrom_buff[buff_counter] & 0xff; // Grab lower byte
         counter++;
          second_byte = recvfrom_buff[buff_counter] >> 8; // Grab upper byte
          counter++;
          buff_counter++;
          printf("%c%c", first_byte, second_byte);
          }
          printf("\n");
      }
  }


  close(udp_socket);
  return 0;
}

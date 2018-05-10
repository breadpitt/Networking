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
#include "SUCMS.h"
#include <openssl/md5.h>
#include <netdb.h>
/**
Project 1 sucms_list.cpp
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
  struct sockaddr_in server_addr;
  // IPv4 structure representing the IP address and port of responding server
  //struct sockaddr_in server_addr;
  struct sockaddr from;
  // Holds the length of the server ip address
  socklen_t from_addr_length;
  from_addr_length = sizeof(struct sockaddr);
  // Variable used to store a user's name
  std::string username = "nate";
  // Variable used to store a user's password
  std::string password = "test";


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

    ret = connect(udp_socket, results->ai_addr, results->ai_addrlen);
      if (ret != 0){
        freeaddrinfo(results);
        std::cout << "Failure to connect to " << ip_string << "\n";
        return 1;
      }
  }

  freeaddrinfo(results);
  char send_buffer[1400];
  SUCMSHeader sucms_header; 
//enum
  SUCMSMessageTypes sucms_messagetype;
  sucms_messagetype= MSG_COMMAND;
  SUCMSCommands command_type;
  command_type=COMMAND_LIST;
  CommandMessage command_message;
  //check!
  sucms_header.sucms_msg_type = htons(sucms_messagetype);
  sucms_header.sucms_msg_length = htons(20+username.length());
  command_message.username_len = htons(username.length());
  command_message.command = htons(command_type);
  //MD5_Update(&password,password,password.length());
  MD5((unsigned char*)password.c_str(),password.length(),command_message.password_hash);
  memset(&send_buffer,0,1400);
  memcpy(&send_buffer[0],&sucms_header,4);
  memcpy(&send_buffer[4],&command_message,20);
  strcpy(&send_buffer[24],username.c_str());
  //sends the first message containing header + command message + username
  ret = send(udp_socket,&send_buffer,sizeof(send_buffer),0);
  memset(&send_buffer,0,1400);
  ret = recv(udp_socket,send_buffer,1400,0);
  int header_type;
  memcpy(&header_type,&send_buffer[4],2);
  sucms_header.sucms_msg_type = ntohs(header_type);
   switch(sucms_header.sucms_msg_type)
    {
     case 10:{std::cout<<"AUTH_OK"<<"\n";break;};
     case 11:{std::cout<<"AUTH_FAILED"<<"\n";break;};
     case 12:{std::cout<<"ACCESS_DENIED"<<"\n";break;};
    }

  CommandResponse command_response;
  //get response message
  memcpy(&command_response,&send_buffer[4],10);
  //record how large the message we are expecting
  int response_code;
  memcpy(&response_code,&send_buffer[4],2);
  response_code = ntohs(response_code);
  int resultx_id;
  memcpy(&resultx_id,&send_buffer[6],2);
  resultx_id = ntohs(resultx_id);
  int message_size;
  memcpy(&message_size,&send_buffer[8],4);
  message_size = ntohs(message_size);
  int message_count;
  memcpy(&message_count,&send_buffer[12],2);
  message_count = ntohs(message_count);
  //Client send header+commandmessage + username + clientgetresult
  command_type= COMMAND_CLIENT_GET_RESULT;
  sucms_header.sucms_msg_type = htons(sucms_messagetype);
  command_message.command = htons(command_type);
  command_type =  COMMAND_LIST;
  SUCMSClientGetResult client_get_result;
  SUCMSFileListResult file_list_result;
  SUCMSFileInfo file_info;
  client_get_result.result_id=  htons(resultx_id);
  client_get_result.command_type = htons(command_type);
  sucms_header.sucms_msg_length= htons(20+6+username.length());
  memset(&send_buffer,0,1400);
  memcpy(&send_buffer[0],&sucms_header,4);
  memcpy(&send_buffer[4],&command_message,20);
  strcpy(&send_buffer[24],username.c_str());
  memcpy(&send_buffer[24+username.length()],&client_get_result,6);
  ret = send(udp_socket,&send_buffer,sizeof(send_buffer),0);
  for(int i = 0;i<message_count;i++)
  {
  ret = recv(udp_socket,send_buffer,1400,0);
  std::cout<<"Message recv"<<ret<<"\n";
  memcpy(&header_type,&send_buffer[0],2);
  sucms_header.sucms_msg_type = ntohs(header_type);
  switch(sucms_header.sucms_msg_type)
      {
      case 52:{
      int  file_length;
      int filename_length;
      int message_number_check;
      int offset=8;
      while(offset<ret){
      memcpy(&message_number_check,&send_buffer[6],2);
      message_number_check = ntohs(message_number_check);
      memcpy(&filename_length,&send_buffer[offset],2);
      filename_length = ntohs(filename_length);
       char filename[filename_length+1];
       filename[filename_length]='\0';
      memcpy(&file_length,&send_buffer[offset+4],4);
      file_length = ntohl(file_length);
      memcpy(&filename,&send_buffer[offset+8],filename_length);
      offset=offset+8+filename_length;
      std::cout<<"File list entry: "<<filename <<" of size "<<file_length<<" bytes\n";}
      }
      }

  }





  return 0;
}

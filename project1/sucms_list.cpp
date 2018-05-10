
/**
 * James Shannon
 * 
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

using std::cerr;
using std::cin;
using std::cout;
using std::getline;
using std::ifstream;
using std::istringstream;
using std::string;
using std::vector;

std::string get_username() {
std::string username;
std::cout << "Enter username: ";
std::getline(std::cin, username);
return username;
}

std::string get_password(){
std::string password;
std::cout << "Enter password: ";
std::getline(std::cin, password);
return password;
}

int main(int argc, char *argv[])
{
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

  //string username;
  // Variable used to store a user's password
  //string password;
  // Variable used to store a user's permissions
  string permissions;

  struct addrinfo hints;
  struct addrinfo *results;

  // Note: this needs to be 4, because the program name counts as an argument!
  if (argc < 3)
  { // change back to 4 after hard code testing
    std::cerr << "Please specify IP PORT FILE as first three arguments." << std::endl;
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];
  //string fileName(argv[3]);

  /*
    std::cout << "Please enter your username: \n";
    std::cin >> username;
    std::cout << "Please enter your password: \n";
    std::cin >> password;
    //permissions = "rwd";
    */

  string username = get_username();
  string password = get_password();

  //username = "nate"; // hardcode for now
  int username_len = strlen(username.c_str());
  //password = "test";

  // Create the UDP socket
  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

  if (udp_socket == -1)
  {
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
  if (ret != 0)
  {
    std::cerr << "Getaddrinfo failed with error " << ret << std::endl;
    perror("getaddrinfo");
    return 1;
  }

  if (results != NULL)
  {
    std::cout << "Trying to connect \n";
    ret = connect(udp_socket, results->ai_addr, results->ai_addrlen);
    if (ret != 0)
    {
      freeaddrinfo(results);
      std::cout << "Failure to connect to " << ip_string << "\n";
      return 1;
    }
  }
  std::cout << "Connection Successful\nSending Data\n";
  freeaddrinfo(results);

  CommandMessage commandMessage; // Create the command message
  commandMessage.username_len = strlen(username.c_str());
  commandMessage.command = 80; // 80 is LIST

  commandMessage.username_len = htons(commandMessage.username_len);
  commandMessage.command = htons(commandMessage.command);

  MD5((unsigned char *)password.c_str(),
      strlen(password.c_str()), commandMessage.password_hash);

  SUCMSHeader messageHeader;
  messageHeader.sucms_msg_type = 50;                                                  // Command type
  messageHeader.sucms_msg_length = sizeof(commandMessage) + strlen(username.c_str()); // 20 + usrn len

  messageHeader.sucms_msg_type = htons(messageHeader.sucms_msg_type);
  messageHeader.sucms_msg_length = htons(messageHeader.sucms_msg_length);

  int CmndHdrSize = sizeof(messageHeader) + sizeof(commandMessage); // 24
  // Create a buffer to send data & 0 out
  char sendBuf[CmndHdrSize + strlen(username.c_str())];
  memset(&sendBuf, 0, sizeof(sendBuf));

  memcpy(&sendBuf[0], &messageHeader, sizeof(messageHeader));
  memcpy(&sendBuf[sizeof(messageHeader)], &commandMessage, CmndHdrSize);
  strcpy(&sendBuf[CmndHdrSize], username.c_str());

  // SEND FIRST message with header | command message | username
  ret = send(udp_socket, sendBuf, sizeof(sendBuf), 0);
  // Check if send worked
  if (ret == -1)
  {
    std::cerr << "Failed to send data!" << std::endl;
    close(udp_socket);
    return 1;
  }

  // Set up to receive response
  char recvBuf[1400];                                   // 1400 is about the largest a packet can be so let's make it that
  memset(&recvBuf, 0, 1400);                            // Clear buffer

  // RECV FIRST response as header | command response
  ret = recv(udp_socket, &recvBuf, sizeof(recvBuf), 0); // Receive up to 1400 uint16s of data

  if (ret < 4)
  {
    std::cerr << "Failed to recv!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  CommandResponse commandResponse;
  uint16_t messageType, messageLength;          // sucms message type and length
  uint16_t commandCode, resultID, messageCount; // command response variables
  uint32_t messageDataSize;                     // Size of data received by command response

  int buffIndex = 0;
  memcpy(&messageType, &recvBuf[0], sizeof(messageHeader.sucms_msg_type));
  messageHeader.sucms_msg_type = ntohs(messageType);
  buffIndex = sizeof(messageHeader.sucms_msg_type); // 4
  memcpy(&messageLength, &recvBuf[buffIndex], sizeof(messageHeader.sucms_msg_length));
  buffIndex += sizeof(messageHeader.sucms_msg_length); // 8
  messageHeader.sucms_msg_length = ntohs(messageLength);
  memcpy(&commandCode, &recvBuf[buffIndex], sizeof(commandResponse.command_response_code));
  commandResponse.command_response_code = ntohs(commandCode);
  buffIndex += sizeof(commandResponse.command_response_code); //12

  memcpy(&resultID, &recvBuf[buffIndex], sizeof(commandResponse.result_id));
  commandResponse.result_id = ntohs(resultID);
  std::cout << "result_id " << commandResponse.result_id << std::endl;

  buffIndex += sizeof(commandResponse.result_id); // 16

  memcpy(&messageDataSize, &recvBuf[buffIndex], sizeof(commandResponse.message_data_size));
  commandResponse.message_data_size = ntohl(messageDataSize);
  buffIndex += sizeof(commandResponse.message_data_size);

  memcpy(&messageCount, &recvBuf[buffIndex], sizeof(commandResponse.message_count));
  commandResponse.message_count = ntohs(messageCount);

  /*
  std::cout << "commandCode: " << commandResponse.command_response_code << "\n";
  std::cout << "result id: " << commandResponse.result_id << "\n";
  std::cout << "message count: " << commandResponse.message_count << "\n";
  std::cout << "message data size: " << commandResponse.message_data_size << "\n";
*/
  switch (commandResponse.command_response_code)
  {
  case 10:
    std::cout << "AUTH_OK\n";
    break;
  case 11:
    std::cout << "AUTH_FAILED\n";
    break;
  }

  // Set up to reply header | command message | username | getresult
  // Can reuse the same header -> command needs to change one value
  // Set the message id value!

  SUCMSClientGetResult getResult;
  getResult.command_type = htons(80);
  getResult.result_id = htons(resultID); // no need to convert back and forth
  //getResult.message_number = 0;

  commandMessage.command = htons(84); // 84 is CLIENT_GET_RESULT
  //commandMessage.command = htons(commandMessage.command);

  messageHeader.sucms_msg_length = htons(sizeof(commandMessage) + username_len + sizeof(getResult));
  std::cout << "result_id " << getResult.result_id << std::endl;
  int replyBufSize = sizeof(messageHeader) + sizeof(commandMessage) + username_len + sizeof(getResult);
  char replyBuf[replyBufSize];
  buffIndex = 0;
  memcpy(&replyBuf[0], &messageHeader, sizeof(messageHeader));
  buffIndex += sizeof(messageHeader);
  memcpy(&replyBuf[buffIndex], &commandMessage, sizeof(commandMessage));
  buffIndex += sizeof(commandMessage); // 24
  strcpy(&replyBuf[buffIndex], username.c_str());
  buffIndex += username_len;
  memcpy(&replyBuf[buffIndex], &getResult, sizeof(getResult));

  ret = send(udp_socket, &replyBuf, sizeof(replyBuf), 0);

  // Check if send worked, clean up and exit if not.
  if (ret == -1)
  {
    std::cerr << "Failed to send data!" << std::endl;
    close(udp_socket);
    return 1;
  }
  std::cout << "SENT  " << ret << " bytes." << std::endl;

  // Set up to receive server header | FileListResult | list[fileInfo | filename]
  memset(&recvBuf, 0, 1400); // Clear buffer
  SUCMSFileListResult fileListResult;
  uint16_t message_number;

  SUCMSFileInfo fileInfo;
  uint16_t filename_len;
  uint32_t file_size;
  for (int i = 0; i < commandResponse.message_count; i++)
  {
    buffIndex = 0;

    ret = recv(udp_socket, recvBuf, 1400, 0);
    std::cout << "Message recv" << ret << "\n";

    // Parse the message header
    memcpy(&messageType, &recvBuf[0], sizeof(messageHeader.sucms_msg_type));
    messageType = ntohs(messageType);
    buffIndex = sizeof(messageHeader.sucms_msg_type); // 2
    memcpy(&messageLength, &recvBuf[buffIndex], sizeof(messageHeader.sucms_msg_length));
    buffIndex += sizeof(messageHeader.sucms_msg_length); // 4
    messageLength = ntohs(messageLength);

    // Parse the list file result
    memcpy(&resultID, &recvBuf[buffIndex], sizeof(fileListResult.result_id));
    resultID = ntohs(resultID);
    buffIndex += sizeof(fileListResult.result_id); // 6
    memcpy(&message_number, &recvBuf[buffIndex], sizeof(fileListResult.message_number));
    message_number = ntohs(message_number);
    buffIndex += sizeof(fileListResult.message_number); //8

    std::cout << "rMessage type: " << messageType << "\n";
    std::cout << "rMessage Len: " << messageHeader.sucms_msg_length << "\n";
    std::cout << "List file result id: " << fileListResult.result_id << "\n";
    std::cout << "List file message number: " << fileListResult.message_number << "\n";
    // Parse the file info
    while (buffIndex < ret)
    {
      memcpy(&filename_len, &recvBuf[buffIndex], sizeof(fileInfo.filename_len));
      fileInfo.filename_len = ntohs(filename_len);
      buffIndex += (sizeof(fileInfo.filename_len) + sizeof(fileInfo.total_pieces)); // Force index to avoid copying varuable not used in list
      memcpy(&file_size, &recvBuf[buffIndex], sizeof(fileInfo.filesize_bytes));
      buffIndex += sizeof(fileInfo.filesize_bytes);

      char filename[fileInfo.filename_len + 1];
      filename[fileInfo.filename_len] = '\0';
      memcpy(&filename, &recvBuf[buffIndex], fileInfo.filename_len);
      buffIndex += fileInfo.filename_len;

      std::cout << "File list entry: " << filename << " of size " << fileInfo.filesize_bytes << " bytes\n";
    }
  }

  close(udp_socket);
  return 0;
}
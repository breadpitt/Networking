
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

std::string get_username()
{
  std::string username;
  std::cout << "Enter username: ";
  std::getline(std::cin, username);
  return username;
}

std::string get_password()
{
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

  struct addrinfo hints;
  struct addrinfo *results;

  // Note: this needs to be 4, because the program name counts as an argument!
  if (argc < 3)
  { // change back to 4 after hard code testing
    std::cerr << "Please specify IP PORT as first two arguments." << std::endl;
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];

  string username = get_username();
  string password = get_password();

  int username_len = strlen(username.c_str());

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
    ret = connect(udp_socket, results->ai_addr, results->ai_addrlen);
    if (ret != 0)
    {
      freeaddrinfo(results);
      std::cout << "Failure to connect to " << ip_string << "\n";
      return 1;
    }
  }

  freeaddrinfo(results);

  CommandMessage commandMessage; // Create the command message
  commandMessage.username_len = username_len;
  commandMessage.command = 80; // 80 is LIST

  commandMessage.username_len = htons(commandMessage.username_len);
  commandMessage.command = htons(commandMessage.command);

  MD5((unsigned char *)password.c_str(),
      strlen(password.c_str()), commandMessage.password_hash);

  SUCMSHeader messageHeader;
  messageHeader.sucms_msg_type = 50;                                      // Command type
  messageHeader.sucms_msg_length = sizeof(commandMessage) + username_len; // 20 + usrn len

  messageHeader.sucms_msg_type = htons(messageHeader.sucms_msg_type);
  messageHeader.sucms_msg_length = htons(messageHeader.sucms_msg_length);

  int CmndHdrSize = sizeof(messageHeader) + sizeof(commandMessage); // 24
  // Create a buffer to send data & 0 out
  char sendBuf[CmndHdrSize + username_len];
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
  char recvBuf[2800];        // bigger is safer I guess
  memset(&recvBuf, 0, 2800); // Clear buffer

  // RECV FIRST response as header | command response
  ret = recv(udp_socket, &recvBuf, sizeof(recvBuf), 0);

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

  buffIndex += sizeof(commandResponse.result_id); // 16

  memcpy(&messageDataSize, &recvBuf[buffIndex], sizeof(commandResponse.message_data_size));
  commandResponse.message_data_size = ntohl(messageDataSize);
  buffIndex += sizeof(commandResponse.message_data_size);

  memcpy(&messageCount, &recvBuf[buffIndex], sizeof(commandResponse.message_count));

  
  switch (commandResponse.command_response_code)
  {
  case 10:
    std::cout << "AUTH_OK\n";
    break;
  case 11:
    std::cout << "Received AUTH_FAILED from server.\n";
    return 1;
  case 15:
    std::cout << "INTERNAL_SERVER_ERROR\n";
    return 1;
  case 16:
    std::cout << "INVALID_CLIENT_MESSAGE\n";
    return 1;
  default:
    std::cout << "YOU DONKED UP!\n";
    return 1;
  }

  // Set up to reply header | command message | username | getresult
  // in hindsight declaring a new header and command message would've saved a lot of headache

  SUCMSClientGetResult getResult; // use LIST command?
  getResult.command_type = 80;
  getResult.command_type = htons(getResult.command_type);
  getResult.result_id = resultID;

  CommandMessage secondCommand;

  commandMessage.username_len = username_len;
  commandMessage.command = 84; // 84 is GET_RESULT

  commandMessage.username_len = htons(commandMessage.username_len);
  commandMessage.command = htons(commandMessage.command);

  messageHeader.sucms_msg_type = htons(50);
  messageHeader.sucms_msg_length = htons(sizeof(commandMessage) + username_len + sizeof(getResult));

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

  // SEND SECOND second command
  ret = send(udp_socket, &replyBuf, sizeof(replyBuf), 0);

  // Check if send worked, clean up and exit if not.
  if (ret == -1)
  {
    std::cerr << "Failed to send data!" << std::endl;
    close(udp_socket);
    return 1;
  }

  // Set up to receive server header | FileListResult | list[fileInfo | filename]
  memset(&recvBuf, 0, 2800); // Clear buffer
  SUCMSFileListResult fileListResult;
  uint16_t message_number = 0;
  fileListResult.message_number = 0;
  SUCMSFileInfo fileInfo;
  uint16_t filename_len;
  uint32_t file_sizeBytes;

  do
  {
    buffIndex = 0;

    // RECV FINAL message(s)
    memset(&recvBuf, 0, 2800); // Clear buffer
    ret = recv(udp_socket, recvBuf, 2800, 0);

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
    buffIndex += sizeof(fileListResult.message_number); //8

    // Parse the file info
    while (buffIndex < ret - ((sizeof(messageHeader) + sizeof(fileListResult))))
    {
      file_sizeBytes = 0;
      memcpy(&filename_len, &recvBuf[buffIndex], sizeof(fileInfo.filename_len));
      fileInfo.filename_len = ntohs(filename_len);
      buffIndex += 4; // hard coding because somethings off :/ (sizeof(fileInfo.filename_len) + sizeof(fileInfo.total_pieces)); // jump to where fileInfo file size is stored
      memcpy(&file_sizeBytes, &recvBuf[buffIndex], sizeof(fileInfo.filesize_bytes));
      //fileInfo.filesize_bytes = ntohl(fileInfo.filesize_bytes);
      file_sizeBytes = ntohl(file_sizeBytes);
      buffIndex += sizeof(fileInfo.filesize_bytes);

      char filename[fileInfo.filename_len + 1];

      filename[fileInfo.filename_len] = '\0';
      memcpy(&filename, &recvBuf[buffIndex], fileInfo.filename_len);
      buffIndex += fileInfo.filename_len;

      printf("File list entry: %s of size %u\n", filename, file_sizeBytes); // << filename << " of size " << file_sizeBytes << " bytes.\n";
    }
  } while (message_number < (messageCount - 256));
  close(udp_socket);
  return 0;
}

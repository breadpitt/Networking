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

using std::cerr;
using std::cin;
using std::cout;
using std::getline;
using std::ifstream;
using std::istringstream;
using std::string;
using std::vector;
/*
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
*/
int main(int argc, char *argv[])
{
    // Alias for argv[1] for convenience
    char *ip_string;
    // Alias for argv[2] for convenience
    char *port_string;
    // Alias for argv[3] for convience
    string filename;
    // Port to send UDP data to. Need to convert from command line string to a number
    unsigned int port;
    // The socket used to send UDP data on
    int udp_socket;
    // Variable used to check return codes from various functions
    int ret;

    string username = "nate"; // hardcode for now;
    // Variable used to store a user's password
    string password = "test";
    // Variable used to store a user's permissions
    string permissions;

    struct addrinfo hints;
    struct addrinfo *results;

    // Note: this needs to be 4, because the program name counts as an argument!
    if (argc < 4)
    {
        std::cerr << "Please specify IP PORT FILE as first three arguments." << std::endl;
        return 1;
    }
    // Set up variables "aliases"
    ip_string = argv[1];
    port_string = argv[2];
    filename = argv[3];

    /*
    std::cout << "Please enter your username: \n";
    std::cin >> username;
    std::cout << "Please enter your password: \n";
    std::cin >> password;
    //permissions = "rwd";
    */

    //get_username();
    //get_password();

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
    commandMessage.command = 81; // 81 is READ / send back file

    commandMessage.username_len = htons(commandMessage.username_len);
    commandMessage.command = htons(commandMessage.command);

    MD5((unsigned char *)password.c_str(),
        strlen(password.c_str()), commandMessage.password_hash);

    SUCMSHeader messageHeader;
    messageHeader.sucms_msg_type = 50; // Command type
    messageHeader.sucms_msg_length = sizeof(commandMessage) + strlen(username.c_str());

    messageHeader.sucms_msg_type = htons(messageHeader.sucms_msg_type);
    messageHeader.sucms_msg_length = htons(messageHeader.sucms_msg_length);

    SUCMSClientFileRWRequest readRequest;
    readRequest.filename_length = strlen(filename.c_str());
    // I'm guessing the server grabs the filename length and skips over these
    // two but just in case...
    readRequest.result_id = 0;
    readRequest.filename_length = 0;
    
    // Create a buffer to send data
    // should be 28 + username and filename bytes long
    int sendBufSize = sizeof(commandMessage) + sizeof(messageHeader) + strlen(username.c_str()) + sizeof(readRequest) + strlen(filename.c_str());
    char sendBuf[sendBufSize];
    int bufIndex = 0;
    memcpy(&sendBuf[0], &messageHeader, 4);
    bufIndex += 4; // 4
    memcpy(&sendBuf[bufIndex], &commandMessage, 20);
    bufIndex += 20; // 24
    strcpy(&sendBuf[bufIndex], username.c_str());
    bufIndex += strlen(username.c_str()); // 24 + usrn len
    memcpy(&sendBuf[bufIndex], &readRequest, 8);
    bufIndex += 8; //24 + usrn len + 8
    strcpy(&sendBuf[bufIndex], filename.c_str());


    // send first message with header | command message | username
    ret = send(udp_socket, sendBuf, sizeof(sendBuf), 0);
    // Check if send worked
    if (ret == -1)
    {
        std::cerr << "Failed to send data!" << std::endl;
        close(udp_socket);
        return 1;
    }
    std::cout << "Sent " << ret << " bytes out.\n";

    // Set up to receive server header | command response
    uint16_t recvBuf[1400];                               // 1400 is about the largest a packet can be so let's make it that
    ret = recv(udp_socket, &recvBuf, sizeof(recvBuf), 0); // Receive up to 1400 uint16s of data

    CommandResponse commandResponse;
    uint16_t messageType, messageLength;          // sucms message type and length
    uint16_t commandCode, resultID, messageCount; // command response variables
    uint32_t messageDataSize;                     // Size of data received by command response

    if (ret < 4)
    {
        std::cerr << "Failed to recv!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    std::cout << "Received " << ret << " bytes." << std::endl;
    memcpy(&messageType, &recvBuf[0], 2);
    messageHeader.sucms_msg_type = ntohs(messageType);
    memcpy(&messageLength, &recvBuf[2], 2);
    messageHeader.sucms_msg_length = ntohs(messageLength);
    memcpy(&commandCode, &recvBuf[4], 2);
    commandResponse.command_response_code = ntohs(commandCode);
    std::cout << "commandCode: " << commandResponse.command_response_code << "\n";
    memcpy(&resultID, &recvBuf[6], 2);
    commandResponse.result_id = ntohs(resultID);
    std::cout << "result id: " << commandResponse.result_id << "\n";
    memcpy(&messageDataSize, &recvBuf[8], 4);
    commandResponse.message_data_size = ntohl(messageDataSize);
    std::cout << "message data size: " << commandResponse.message_data_size << "\n";
    memcpy(&messageCount, &recvBuf[12], 2);
    commandResponse.message_count = ntohs(messageCount);
    std::cout << "message count: " << commandResponse.message_count << "\n";

    switch (commandCode)
    {
    case 10:
        std::cout << "AUTH_OK\n";
        break;
    case 11:
        std::cout << "AUTH_FAILED\n";
        break;
    case 12:
        std::cout << "ACCESS_DENIED\n";
        break;
    case 13:
        std::cout << "NO_SUCH_FILE\n";
        break;
    case 14:
        std::cout << "INVALID_RESULT_ID\n";
        break;
    case 15:
        std::cout << "INTERNAL_SERVER_ERROR\n";
        break;
    case 16:
        std::cout << "INVALID_CLIENT_MESSAGE\n";
    }

    SUCMSClientGetResult fileRead;
    fileRead.command_type = htons(81); // 81 is READ / request files to be sent
    fileRead.result_id = commandResponse.result_id;
    fileRead.message_number = 0;
    int readReqSize = sizeof(commandMessage) + sizeof(messageHeader) + strlen(username.c_str()) + sizeof(fileRead);
    char fileReadBuf[sendBufSize];
    
    for (int i = 0; i < commandResponse.message_count; i++)
  {
    ret = recv(udp_socket, recvBuf, 1400, 0);
    std::cout << "Message recv" << ret << "\n";
    memcpy(&messageType, &recvBuf[0], 2);
    messageHeader.sucms_msg_type = ntohs(messageType);

   
  }




    close(udp_socket);
    return 0;
}

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

std::string get_filename()
{
    std::string filename;
    std::cout << "Enter filename: ";
    std::getline(std::cin, filename);
    return filename;
}

int main(int argc, char *argv[])
{
    // Alias for argv[1] for convenience
    char *ip_string;
    // Alias for argv[2] for convenience
    char *port_string;
    //string filename;
    // Port to send UDP data to. Need to convert from command line string to a number
    unsigned int port;
    // The socket used to send UDP data on
    int udp_socket;
    // Variable used to check return codes from various functions
    int ret;

    //string username = "nate"; // hardcode for now;
    // Variable used to store a user's password
    //string password = "test";
    //string filename = "test.txt";
    struct addrinfo hints;
    struct addrinfo *results;

    if (argc < 3)
    {
        std::cerr << "Please specify IP PORT FILE as first three arguments." << std::endl;
        return 1;
    }
    // Set up variables "aliases"
    ip_string = argv[1];
    port_string = argv[2];
    //filename = argv[3];

    /*
    std::cout << "Please enter your username: \n";
    std::cin >> username;
    std::cout << "Please enter your password: \n";
    std::cin >> password;
    //permissions = "rwd";
    */

    string username = get_username();
    string password = get_password();
    string filename = get_filename();

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
    int username_len = strlen(username.c_str());
    int filename_len = strlen(filename.c_str());
    CommandMessage commandMessage; // Create the command message
    commandMessage.username_len = username_len;
    commandMessage.command = 83; // 83 is DELETE

    commandMessage.username_len = htons(commandMessage.username_len);
    commandMessage.command = htons(commandMessage.command);

    MD5((unsigned char *)password.c_str(),
        strlen(password.c_str()), commandMessage.password_hash);

    SUCMSClientFileRWRequest deleteRequest;
    deleteRequest.filename_length = filename_len;
    deleteRequest.filename_length = htons(deleteRequest.filename_length);


    SUCMSHeader messageHeader;
    messageHeader.sucms_msg_type = 50; // Command type
    messageHeader.sucms_msg_length = sizeof(commandMessage) + sizeof(deleteRequest) +
                                                 username_len + filename_len;

    messageHeader.sucms_msg_type = htons(messageHeader.sucms_msg_type);
    messageHeader.sucms_msg_length = htons(messageHeader.sucms_msg_length);
    // should be 32 + username and filename bytes long
    int sendBufSize = sizeof(messageHeader) + sizeof(commandMessage) +
                      sizeof(deleteRequest) + username_len + filename_len; 

    // Create a buffer to send data & 0 out
    char sendBuf[sendBufSize];
    memset(&sendBuf, 0, sizeof(sendBuf));

    int buffIndex = 0;
    memcpy(&sendBuf[buffIndex], &messageHeader, sizeof(messageHeader));
    buffIndex += sizeof(messageHeader); // i = 4
    memcpy(&sendBuf[buffIndex], &commandMessage, sizeof(commandMessage));
    buffIndex += sizeof(commandMessage); // i = 24
    strcpy(&sendBuf[buffIndex], username.c_str());
    buffIndex += username_len; // i = 28 (for "nate" at least)
    memcpy(&sendBuf[buffIndex], &deleteRequest, sizeof(deleteRequest));
    buffIndex += sizeof(deleteRequest); //36
    strcpy(&sendBuf[buffIndex], filename.c_str());

    // SEND FIRST message with header | command message | username
    ret = send(udp_socket, sendBuf, sizeof(sendBuf), 0);
    // Check if send worked
    if (ret == -1)
    {
        std::cerr << "Failed to send data!" << std::endl;
        close(udp_socket);
        return 1;
    }
    std::cout << "Sent " << ret << " bytes out.\n";

    
    char recvBuf[1400];

    // RECV FIRST response header | command response
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

    buffIndex = 0;
    memcpy(&messageType, &recvBuf[0], sizeof(messageHeader.sucms_msg_type));
    messageHeader.sucms_msg_type = ntohs(messageType);
    buffIndex = sizeof(messageHeader.sucms_msg_type); // 2
    memcpy(&messageLength, &recvBuf[buffIndex], sizeof(messageHeader.sucms_msg_length));
    buffIndex += sizeof(messageHeader.sucms_msg_length); // 6
    messageHeader.sucms_msg_length = ntohs(messageLength);
    memcpy(&commandCode, &recvBuf[buffIndex], sizeof(commandResponse.command_response_code));
    commandResponse.command_response_code = ntohs(commandCode);
    buffIndex += sizeof(commandResponse.command_response_code); //8

    std::cout << "commandCode: " << commandResponse.command_response_code << "\n";
    //std::cout << "result id: " << commandResponse.result_id << "\n";
    //std::cout << "message count: " << commandResponse.message_count << "\n";
    //std::cout << "message data size: " << commandResponse.message_data_size << "\n";

    switch (commandResponse.command_response_code)
    {
    case 10:
        std::cout << "FILE_DELETED\n";
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
    case 15:
        std::cout << "INTERNAL_SERVER_ERROR\n";
        break;
    case 16:
        std::cout << "INVALID_CLIENT_MESSAGE\n";
        break;
    }

    close(udp_socket);
    return 0;
}
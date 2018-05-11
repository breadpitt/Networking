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

    struct addrinfo hints;
    struct addrinfo *results;

    if (argc < 3)
    {
        std::cerr << "Please specify IP PORT as first two arguments." << std::endl;
        return 1;
    }
    // Set up variables "aliases"
    ip_string = argv[1];
    port_string = argv[2];

    // Set up user input
    string username = get_username();
    string password = get_password();
    string filename = get_filename();
    int username_len = strlen(username.c_str());
    int password_len = strlen(password.c_str());
    int filename_len = strlen(filename.c_str());

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
    commandMessage.username_len = htons(username_len);
    commandMessage.command = htons(81); // 81 is READ

    MD5((unsigned char *)password.c_str(),
        strlen(password.c_str()), commandMessage.password_hash);

    SUCMSClientFileRWRequest readFile;
    readFile.filename_length = htons(filename_len);
    readFile.result_id = htons(0);

    int messageSize = sizeof(commandMessage) + sizeof(readFile) +
                      username_len + filename_len;
    SUCMSHeader messageHeader;
    messageHeader.sucms_msg_type = htons(50); // Command type COMMAND
    messageHeader.sucms_msg_length = htons(messageSize);

    // Create a buffer to send data & 0 out
    char sendBuf[sizeof(messageHeader) + messageSize];
    memset(&sendBuf, 0, sizeof(sendBuf));

    int buffIndex = 0;
    memcpy(&sendBuf[buffIndex], &messageHeader, sizeof(messageHeader));
    buffIndex += sizeof(messageHeader);
    memcpy(&sendBuf[buffIndex], &commandMessage, sizeof(commandMessage));
    buffIndex += sizeof(commandMessage);
    strcpy(&sendBuf[buffIndex], username.c_str());
    buffIndex += username_len;
    memcpy(&sendBuf[buffIndex], &readFile, sizeof(readFile));
    buffIndex += sizeof(readFile);
    strcpy(&sendBuf[buffIndex], filename.c_str());

    // SEND FIRST message with header | command message | username | RWRequest |filename
    ret = send(udp_socket, sendBuf, sizeof(sendBuf), 0);
    // Check if send worked
    if (ret == -1)
    {
        std::cerr << "Failed to send data!" << std::endl;
        close(udp_socket);
        return 1;
    }

    // Set up to receive response
    char recvBuf[1400];        // 1400 is about the largest a packet can be so let's make it that
    memset(&recvBuf, 0, 1400); // Clear buffer

    // RECV FIRST response as header | command response
    ret = recv(udp_socket, &recvBuf, sizeof(recvBuf), 0); // Receive up to 1400 uint16s of data

    if (ret < 4)
    {
        std::cerr << "Failed to recv!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }
    SUCMSHeader responseHeader;
    CommandResponse commandResponse;

    if (ret < 4)
    {
        std::cerr << "Failed to recv!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }
    uint16_t resultID, messageCount; //
    buffIndex = 0;
    memcpy(&messageHeader.sucms_msg_type, &recvBuf[0], sizeof(messageHeader.sucms_msg_type));
    messageHeader.sucms_msg_type = ntohs(messageHeader.sucms_msg_type);
    buffIndex = sizeof(messageHeader.sucms_msg_type); // 2

    memcpy(&messageHeader.sucms_msg_length, &recvBuf[buffIndex], sizeof(messageHeader.sucms_msg_length));
    buffIndex += sizeof(messageHeader.sucms_msg_length); // 4
    messageHeader.sucms_msg_length = ntohs(messageHeader.sucms_msg_length);

    memcpy(&commandResponse.command_response_code, &recvBuf[buffIndex], sizeof(commandResponse.command_response_code));
    commandResponse.command_response_code = ntohs(commandResponse.command_response_code);
    buffIndex += sizeof(commandResponse.command_response_code); //6

    memcpy(&resultID, &recvBuf[buffIndex], sizeof(commandResponse.result_id)); // don't convert id
    commandResponse.result_id = ntohs(resultID);
    buffIndex += sizeof(commandResponse.result_id); // 8

    memcpy(&commandResponse.message_data_size, &recvBuf[buffIndex], sizeof(commandResponse.message_data_size));
    commandResponse.message_data_size = ntohl(commandResponse.message_data_size);
    buffIndex += sizeof(commandResponse.message_data_size); // 12

    memcpy(&commandResponse.message_count, &recvBuf[buffIndex], sizeof(commandResponse.message_count));
    commandResponse.message_count = ntohs(commandResponse.message_count); //14
    messageCount = commandResponse.message_count;                         // store

    switch (commandResponse.command_response_code)
    {
    case 10:
        std::cout << "AUTH_OK\n";
        break;
    case 11:
        std::cout << "Received AUTH_FAILED from server.\n";
        return 1;
    case 12:
        std::cout << "Received ACCESS_DENIED from server.\n";
        return 1;
    case 13:
        std::cout << "Received NO_SUCH_FILE from server.\n";
        return 1;
    case 15:
        std::cout << "Received INTERNAL_SERVER_ERROR from server.\n";
        return 1;
    case 16:
        std::cout << "Received INVALID_CLIENT_MESSAGE from server.\n";
        return 1;
    default:
        std::cout << "YOU DONKED UP!\n";
        return 1;
    }

    SUCMSClientGetResult getRead;
    getRead.command_type = htons(81); // READ
    getRead.result_id = resultID;
    getRead.message_number = htons(0);
    commandMessage.command = htons(84); // CLIENT GET RESULTS
    int loopMsgSize = sizeof(commandMessage) + sizeof(getRead) + username_len;
    messageHeader.sucms_msg_length = htons(loopMsgSize);
    // Create a buffer to send data & 0 out
    char loopSendBuf[sizeof(messageHeader) + messageSize];

    // Set up to receive variables (recv buff already initialized)
    SUCMSHeader loopHeader;
    SUCMSFileDataResult loopFDR;
    SUCMSFileData fileData;

    for (int i = 0; i < messageCount; i++)
    {

        memset(&loopSendBuf, 0, sizeof(loopSendBuf));

        buffIndex = 0;
        memcpy(&loopSendBuf[buffIndex], &messageHeader, sizeof(messageHeader));
        buffIndex += sizeof(messageHeader);
        memcpy(&loopSendBuf[buffIndex], &commandMessage, sizeof(commandMessage));
        buffIndex += sizeof(commandMessage);
        strcpy(&loopSendBuf[buffIndex], username.c_str());
        buffIndex += username_len;
        memcpy(&loopSendBuf[buffIndex], &getRead, sizeof(getRead));

        // SEND i message with header | command message | username | ClientGetResult
        ret = send(udp_socket, loopSendBuf, sizeof(loopSendBuf), 0);
        // Check if send worked
        if (ret == -1)
        {
            std::cerr << "Failed to send data!" << std::endl;
            close(udp_socket);
            return 1;
        }

        memset(&recvBuf, 0, 1400); // Clear buffer
        // RECV FIRST response as header | command response
        ret = recv(udp_socket, &recvBuf, sizeof(recvBuf), 0); // Receive up to 1400 uint16s of data

        if (ret < 4)
        {
            std::cerr << "Failed to recv!" << std::endl;
            std::cerr << strerror(errno) << std::endl;
            close(udp_socket);
            return 1;
        }

        buffIndex = 0;
        memcpy(&messageHeader.sucms_msg_type, &recvBuf[0], sizeof(messageHeader.sucms_msg_type)); // be sure to check for bad chunks
        messageHeader.sucms_msg_type = ntohs(messageHeader.sucms_msg_type);
        buffIndex = sizeof(messageHeader.sucms_msg_type); // 2

        memcpy(&messageHeader.sucms_msg_length, &recvBuf[buffIndex], sizeof(messageHeader.sucms_msg_length));
        buffIndex += sizeof(messageHeader.sucms_msg_length); // 4
        messageHeader.sucms_msg_length = ntohs(messageHeader.sucms_msg_length);

        memcpy(&loopFDR.result_id, &recvBuf[0], sizeof(loopFDR.result_id));
        getRead.result_id = loopFDR.result_id;  // Don't know if the result_id changes or not and I don't want to find out
        buffIndex += sizeof(loopFDR.result_id); // 6

        memcpy(&loopFDR.message_number, &recvBuf[buffIndex], sizeof(loopFDR.message_number));
        buffIndex += sizeof(loopFDR.message_number); // 8
        loopFDR.message_number += ntohs(loopFDR.message_number);
        getRead.message_number = loopFDR.message_number;

        memcpy(&loopFDR.file_bytes, &recvBuf[0], sizeof(loopFDR.file_bytes));
        loopFDR.file_bytes = ntohs(loopFDR.file_bytes);
        buffIndex += sizeof(loopFDR.file_bytes); // 10

        memcpy(&loopFDR.byte_offset, &recvBuf[buffIndex], sizeof(loopFDR.byte_offset));
        buffIndex += sizeof(loopFDR.byte_offset); // 14
        loopFDR.byte_offset = ntohl(loopFDR.byte_offset);

        memcpy(&fileData.filedata_length, &recvBuf[0], sizeof(fileData.filedata_length));
        fileData.filedata_length = ntohs(fileData.filedata_length);
        buffIndex += sizeof(fileData.filedata_length); // 16

        switch (commandResponse.command_response_code)
        {
        case 10:
            std::cout << "AUTH_OK\n";
            if (loopFDR.message_number > messageCount)
            {
                std::cout << "Received BAD_CHUNK from server.\n";
            }
            break;
        case 14:
            std::cout << "Received NO_SUCH_RESULT from server.\n";
            return 1;
        default:
            std::cout << "YOU DONKED UP!\n";
            return 1;
        }
    }

    close(udp_socket);
    return 0;
}

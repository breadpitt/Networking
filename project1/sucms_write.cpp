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

    std::ifstream file(filename.c_str());

    if (!file.is_open())
    {
        std::cerr << "Error opening file\n";
        return 1;
    }

    // Get file size and set position back to the beginning
    file.seekg(0, file.end);
    uint32_t filesize = file.tellg();
    file.seekg(0, file.beg);

    //How many 1400 byte packets are needed to send the file
    int totalpieces = (filesize / 1400) + 1;

    std::cout << "filesize: " << filesize << "\n";
    std::cout << "pieces: " << totalpieces << "\n";

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
    commandMessage.command = htons(82); // 82 is CREATE/WRITE

    MD5((unsigned char *)password.c_str(),
        strlen(password.c_str()), commandMessage.password_hash);

    SUCMSFileInfo writeFile;
    writeFile.filename_len = htons(filename_len);
    writeFile.total_pieces = htons(totalpieces);
    writeFile.filesize_bytes = htonl(filesize); /// size of file

    int messageSize = sizeof(commandMessage) + sizeof(writeFile) + username_len + filename_len;

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
    memcpy(&sendBuf[buffIndex], &writeFile, sizeof(writeFile));
    buffIndex += sizeof(writeFile);
    strcpy(&sendBuf[buffIndex], filename.c_str());

    // SEND FIRST message with header | command message | username | FileInfo |filename
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

    uint16_t resultID, messageCount;

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
    //commandResponse.result_id = ntohs(resultID);
    buffIndex += sizeof(commandResponse.result_id); // 8
    std::cout << "firstRESULTID " << resultID << "\n";
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

    // Setup structs and initialize variables
    // I now see why const is used
    SUCMSClientFileData clientFileData;
    SUCMSHeader sendHeader;
    SUCMSHeader recvHeader;
    SUCMSFileDataResponse dataResponse;
    int availableBuf = 1400 - (sizeof(sendHeader) + sizeof(clientFileData) + username_len); // should equal 1348 for nate
    int filesizeIndex = filesize;                                                           // Tracks how much data has been sent

    int fileStreamPos = 0; // Tracks where in the file to read data
    int pieces = 0;        // If there has been a full

    clientFileData.username_len = htons(username_len); // Static
    MD5((unsigned char *)password.c_str(),
        strlen(password.c_str()), clientFileData.password_hash);

    // memcpy(&clientFileData.password_hash[0], &commandMessage.password_hash, 16); // ??? Static

    sendHeader.sucms_msg_type = htons(53); // Static
    uint16_t messageNumber = 1;
    uint16_t fileDataLen = htons(filesize);
    uint16_t sendMessageSize;
    uint32_t result = 0;
    uint16_t FDRtype;

    while (totalpieces > 0)
    {
        {
            // If the filesize is larger than the buffer - headers then set the
            // amount to be copied equal to the max amount of space in the buffer
            // and subtract that amount from a copy of the file size
            if (totalpieces > 1)
            {
                filesizeIndex = filesize - availableBuf;
                filesize = availableBuf;
            }

            file.seekg(clientFileData.filedata_offset);
            std::cout << "TOTAL PIECES: " << totalpieces << "\n";
            std::cout << "FILESIZE: " << filesize << "\n";
            std::cout << "FILESIZE INDEX: " << filesizeIndex << "\n";
            sendMessageSize = sizeof(clientFileData) + username_len + filesize; // Dynamic
            std::cout << "SENDMESSAGESIZE: " << sendMessageSize << "\n";
            sendHeader.sucms_msg_length = htons(sendMessageSize);
            std::cout << "MESSAGE LENGTH (ntohs): " << ntohs(sendHeader.sucms_msg_length) << "\n";
            clientFileData.result_id = resultID; // Static?
            std::cout << "RESULTID " << clientFileData.result_id << "\n";
            clientFileData.filedata_length = htons(filesize); // Dynamic
            std::cout << "FILEDATA LENGTH " << ntohs(clientFileData.filedata_length) << "\n";
            clientFileData.message_number = htons(messageNumber); // Static?
            std::cout << "MESSAGE NUMBER (ntohs) " << ntohs(clientFileData.message_number) << "\n";
            clientFileData.filedata_offset = htonl(result);       // Dynamic

            char writeBuf[sizeof(sendHeader) + sendMessageSize];
            std::cout << "BUFF LENGTH: " << sizeof(writeBuf) << "\n";
            // Standard copy metadata into buffer
            memset(&writeBuf, 0, sizeof(writeBuf));
            buffIndex = 0;
            memcpy(&writeBuf[buffIndex], &sendHeader, sizeof(sendHeader));
            buffIndex += sizeof(sendHeader); // 4
            memcpy(&writeBuf[buffIndex], &clientFileData, sizeof(clientFileData));
            buffIndex += sizeof(clientFileData); //48

            strcpy(&writeBuf[buffIndex], username.c_str());
            buffIndex += username_len; // 52 w/ nate
            std::cout << "BUFF INDEX: " << buffIndex << "\n";
            file.read(&writeBuf[buffIndex], filesize);
            result = file.gcount(); // "Returns the number of characters extracted by the last unformatted input operation."
            std::cout << "Bytes read: " << result << "\n";

            if (result <= 0)
            { // no data to read in
                break;
            }

            // SEND i message with header | command message | username | ClientGetResult
            ret = send(udp_socket, writeBuf, sizeof(writeBuf), 0);

            std::cout << "Bytes sent: " << ret << "\n";
            // Check if send worked
            if (ret == -1)
            {
                std::cerr << "Failed to send data!" << std::endl;
                close(udp_socket);
                return 1;
            }

            // Clear buffer
            memset(&recvBuf, 0, 1400);
            // RECV FIRST response as header | command response
            ret = recv(udp_socket, &recvBuf, sizeof(recvBuf), 0);

            if (ret < 4)
            {
                std::cerr << "Failed to recv!" << std::endl;
                std::cerr << strerror(errno) << std::endl;
                close(udp_socket);
                return 1;
            }

            buffIndex = 0;
            memcpy(&recvHeader.sucms_msg_type, &recvBuf[0], sizeof(recvHeader.sucms_msg_type)); // be sure to check for bad chunks
            recvHeader.sucms_msg_type = ntohs(recvHeader.sucms_msg_type);
            buffIndex = sizeof(recvHeader.sucms_msg_type); // 2

            std::cout << "FILE DATA HEADER: " << recvHeader.sucms_msg_type << "\n";
            if (recvHeader.sucms_msg_type != 54)
            {
                std::cout << "Message type error\n";
                return 1;
            }

            memcpy(&recvHeader.sucms_msg_length, &recvBuf[buffIndex], sizeof(recvHeader.sucms_msg_length));
            buffIndex += sizeof(recvHeader.sucms_msg_length); // 4
            recvHeader.sucms_msg_length = ntohs(recvHeader.sucms_msg_length);
            std::cout << "RECV MESSAGE LENGTH " << recvHeader.sucms_msg_length << "\n";

            memcpy(&FDRtype, &recvBuf[buffIndex], sizeof(dataResponse.filedata_response_type)); // be sure to check for bad chunks
            dataResponse.filedata_response_type = ntohs(FDRtype);
            buffIndex += sizeof(dataResponse.filedata_response_type); // 6
            std::cout << "DATA RESPONSE " << dataResponse.filedata_response_type << "\n";
            memcpy(&messageNumber, &recvBuf[buffIndex], sizeof(dataResponse.message_number)); // Dynamic?
            dataResponse.message_number = ntohs(dataResponse.message_number);
            buffIndex += sizeof(dataResponse.message_number); // 8
            std::cout << "MESSAGE NUMBER " << dataResponse.message_number << "\n";
            memcpy(&resultID, &recvBuf[buffIndex], sizeof(dataResponse.result_id)); // Dynamic?
            buffIndex += sizeof(dataResponse.result_id);                            // 10
                                                                                    //resultID = dataResponse.result_id;
            std::cout << "resultID RESPONSE " << dataResponse.result_id << "\n";

            switch (dataResponse.filedata_response_type)
            {
            case 20:
                std::cout << "FILEDATA_OK\n";
                break;
            case 21:
                std::cout << "Received FILEDATA_AUTH_FAILED from server.\n";
                return 1;
            case 22:
                std::cout << "Received FILEDATA_INVALID_RESULT_ID from server.\n";
                return 1;
            case 23:
                std::cout << "Received FILEDATA_INVALID_CHUNK from server.\n";
                return 1;
            case 24:
                std::cout << "Received FILEDATA_SERVER_ERROR from server.\n";
                return 1;
            case 25:
                std::cout << "Received INVALID_CLIENT_MESSAGE from server.\n";
                return 1;
            default:
                std::cout << "YOU DONKED UP!\n";
                return 1;
            }

            filesize = filesizeIndex;
            totalpieces--;
            clientFileData.filedata_offset += result; // update file stream index
        }                                             // filesize should never be more than available Buf and if it is less than it the last packet should have already been sent
    }

    /*
    std::cout << "SDKFLJ:SDF\n";
    CommandMessage sendComplete; // Create the command message
    sendComplete.username_len = htons(username_len);
    sendComplete.command = htons(85); // no send_complete command?

    MD5((unsigned char *)password.c_str(),
        strlen(password.c_str()), sendComplete.password_hash);

    int sendCompleteSize = sizeof(sendComplete) + username_len;

    SUCMSHeader sendCompleteHeader;
    sendCompleteHeader.sucms_msg_type = htons(50); // Command type COMMAND
    sendCompleteHeader.sucms_msg_length = htons(sendCompleteSize);

    // Create a buffer to send data & 0 out
    char sendCompleteBuf[sizeof(sendCompleteHeader) + sendCompleteSize];
    memset(&sendBuf, 0, sizeof(sendBuf));

    buffIndex = 0;
    memcpy(&sendBuf[buffIndex], &sendCompleteHeader, sizeof(sendCompleteHeader));
    buffIndex += sizeof(sendCompleteHeader);
    memcpy(&sendBuf[buffIndex], &sendComplete, sizeof(sendComplete));
    buffIndex += sizeof(sendComplete);
    strcpy(&sendBuf[buffIndex], username.c_str());
    buffIndex += username_len;
    */
    close(udp_socket);
    return 0;
}


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

using std::cin;
using std::cout;
using std::cerr;
using std::getline;
using std::istringstream;
using std::string;
using std::vector;
using std::ifstream;

std::vector<string> parseFile(string &filename) {

	string line;
	line.clear();
	ifstream pwFile;
	pwFile.open(filename.c_str());
	if (!pwFile.is_open()) {
		cerr << "ERROR: failed to open trace file: " << filename << "\n";
		exit(2);
	}
	vector<string> loginString;
	
	int i = 0;
	// Read next line
	if (std::getline(pwFile, line)) {

		// Make a string stream from command line
		istringstream ss(line);
		string token;

		while (getline(ss, token, ',')) {
			ss.ignore();
			loginString.push_back(token);
			cout << loginString[i] << std::endl;
			i++;
		}
		return loginString;
	}
	else if (pwFile.eof()) {
    cout << "Empty file error\n";
		return loginString;
	}
	else {
		cerr << "ERROR: getline failed for" << filename << "\n";
		exit(2);
	}
}
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
  int udp_socket;
  // Variable used to check return codes from various functions
  int ret;
  // IPv4 structure representing and IP address and port of the destination
  struct sockaddr_in dest_addr;
  // IPv4 structure representing the IP address and port of responding server
  struct sockaddr_in server_addr;
  // Holds the length of the server ip address
  socklen_t server_addr_length;
  server_addr_length = sizeof(struct sockaddr_in);
  // Variable used to store a user's name
  string username;
  // Variable used to store a user's password
  string password;
  // Variable used to store a user's permissions
  string permissions;

  // Set dest_addr to all zeroes, just to make sure it's not filled with junk
  // Note we could also make it a static variable, which will be zeroed before execution
 // memset(&dest_addr, 0, sizeof(struct sockaddr_in));

  // Note: this needs to be 4, because the program name counts as an argument!
  if (argc < 3) { // change back to 4 after hard code testing
    std::cerr << "Please specify IP PORT FILE as first three arguments." << std::endl; 
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];
  //string fileName(argv[3]);


  // uncomment after hardcode testing
  //vector<string> loginArgs = parseFile(fileName); // Open the file and sequentially parse the contents into a vector
  //username = loginArgs[0]; 
  //password = loginArgs[1];
  //permissions = loginArgs[2];
    std::cout << "Please enter your username: \n";
    std::cin >> username;
    std::cout << "Please enter your password: \n";
    std::cin >> password;
    //permissions = "rwd";
  
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
  uint16_t* initMessage = initVector.data();
  //initMessage = new uint16_t[initVector.size()];
  std::copy(initVector.begin(), initVector.end(), initMessage);
   std::cout << "Size of initMessage: " <<  sizeof(initMessage) << "\n";
  /*
  memcpy(initBuf, (const void *)&initHeader, sizeof(initHeader));
  std::cout << "Size of headersize: " <<  initHeaderSize << "\n";
  std::cout << "Size of listsize: " <<  initListSize << "\n";
  memcpy(initBuf + initHeaderSize, (const void *)&initList, sizeof(initList));
   std::cout << "Size of bufsize: " <<  initBufSize << "\n";
  memcpy(initBuf + initHeaderSize + initListSize, username.c_str(), initList.username_len);
  */
  for (int i = 0; i <sizeof(initMessage); i++){
    printf(" %u ", (unsigned int)initMessage[i] );

  }
  // Create the UDP socket.
  // AF_INET is the address family used for IPv4 addresses
  // SOCK_DGRAM indicates creation of a UDP socket
  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

  // Make sure socket was created successfully, or exit.
  if (udp_socket == -1) {
    std::cerr << "Failed to create udp socket!" << std::endl;
    return 1;
  }

  // inet_pton converts an ip address string (e.g., 1.2.3.4) into the 4 byte
  // equivalent required for using the address in code.
  // Note that because dest_addr is a sockaddr_in (again, IPv4) the 'sin_addr'
  // member of the struct is used for the IP
  ret = inet_pton(AF_INET, ip_string, (void *)&dest_addr.sin_addr);

  // Check whether the specified IP was parsed properly. If not, exit.
  if (ret == -1) {
    std::cerr << "Failed to parse IPv4 address!" << std::endl;
    close(udp_socket);
    return 1;
  }

  // Convert the port string into an unsigned integer.
  ret = sscanf(port_string, "%u", &port);
  // sscanf is called with one argument to convert, so the result should be 1
  // If not, exit.
  if (ret != 1) {
    std::cerr << "Failed to parse port!" << std::endl;
    close(udp_socket);
    return 1;
  }

  // Set the address family to AF_INET (IPv4)
  dest_addr.sin_family = AF_INET;
  // Set the destination port. Use htons (host to network short)
  // to ensure that the port is in big endian format
  dest_addr.sin_port = htons(port);

  // Send the data to the destination.
  // Note 1: we are sending strlen(data_string) + 1 to include the null terminator
  // Note 2: we are casting dest_addr to a struct sockaddr because sendto uses the size
  //         and family to determine what type of address it is.
  // Note 3: the return value of sendto is the number of bytes sent
 ret = sendto(udp_socket, &initVector[0], initVector.size(), 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

  // Check if send worked, clean up and exit if not.
  if (ret == -1) {
    std::cerr << "Failed to send data!" << std::endl;
    close(udp_socket);
    return 1;
  }

  std::cout << "Sent " << ret << " bytes out." << std::endl;

  // The header & response should only be about 7 uint_16s but I'm adding some buffer to my buffer
  //  just in case I messed up my counting, which is always possible
  uint16_t recvfrom_buf[32];
  uint16_t messageType, messageLength; // sucms message type and length
  uint16_t commandCode, resultID, messageCount; // command response variables
  uint32_t messageDataSize; // Size of data received by command response 
  ret = recvfrom(udp_socket, &recvfrom_buf, 31, 0, (struct sockaddr *)&server_addr, &server_addr_length); // Receive up to 64 bytes of data

  if (ret < 4) {
    std::cerr << "Failed to recvfrom!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  messageType = ntohs(recvfrom_buf[0]);
  std::cout << "messageType: " << messageType << "\n";
  messageLength = ntohs(recvfrom_buf[1]);
  std::cout << "messageLength: " << messageLength << "\n";
  commandCode = ntohs(recvfrom_buf[2]);
  std::cout << "commandCode: " << commandCode << "\n";
  resultID = ntohs(recvfrom_buf[3]);
  // 32 bit variable likely got chopped up into two 16 bit slots so we need to cast, shift, and cat in order to get it back into the right format
  messageDataSize = (ntohs((uint32_t)recvfrom_buf[4]) << 16) | ntohs(recvfrom_buf[5]);
  std::cout << "messageDataSize: " << messageDataSize << "\n";
  messageCount = (ntohs(recvfrom_buf[6])); 
  std::cout << "messageCount: " << messageCount << "\n";




  close(udp_socket);
  return 0;
}
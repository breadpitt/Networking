#include <iostream>
#include <cstring>
int main() {
    std::string password;
    std::string username;

    std::cout << "Please enter your username: \n";
    std::cin >> username;
    std::cout << "Please enter your password: \n";
    std::cin >> password;
    std::cout << username << "\n" << password << "\n";
    return 0;
}
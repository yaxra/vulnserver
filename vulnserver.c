/**
 * Author: stuxweet
 * Purposefully designed vulnerable server intended for buffer overflow studies.
 * After receiving a connection, the client should send a name. The server, however, won't correctly check the buffer size.
 */

#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#define NTDDI_VERSION 0x06010000

#include <winsock2.h> // Winsock is required for Windows TCP/IP connections
                      // Complete Winsock server source code: https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

HINSTANCE hDll = NULL;

/**
 * WHAT IS A SOCKET?
 * A socket is a connection point between two processes, so they can communicate with each other
 * It has an address, which is IP + Port
 * Here we're talking about stream sockets (TCP) ;^)
 */

#define DEFAULT_PORT "9999" // This is the port the listen socket will listen to, waiting for connections

 /**
  * PRINTS OUT THE RECEIVED NAME
  */
void received_name(const char *name) 
{
    printf("[*] Name received: %s\n", name);
}

/**
 * HANDLES CLIENT COMMUNICATION
 */
void handle_client(SOCKET client_sock)
{
    char buffer[500]; // Allocated buffer

    const char *msg = "Enter your name: ";
    send(client_sock, msg, strlen(msg), 0);

    int received = recv(client_sock, buffer, 1000, 0); // VULNERABILITY: Reads up to 1000 bytes into a 500 byte buffer
    if (received <= 0)
    {
        printf("[-] Connection closed by client\n");
        closesocket(client_sock);
        return;
    }

    /**
     * Corrects the data so that it is a valid string in C
     */
    buffer[received] = '\0';

    int i;
    for (i = 0; i < received; i++)
    {
        if (buffer[i] == '\r' || buffer[i] == '\n')
        {
            buffer[i] = '\0';
            break;
        }
    }

    received_name(buffer);

    char welcome_msg[600];
    sprintf(welcome_msg, "Welcome, %s!\n", buffer);
    send(client_sock, welcome_msg, strlen(welcome_msg), 0);

    closesocket(client_sock);
}

/**
 * MAIN FUNCTION
 */
int main()
{
    hDll = LoadLibrary("serverdll.dll");
    if (!hDll)
    {
        printf("[!] Error loading DLL: %lu\n", GetLastError());
        return 1;
    }

    WSADATA wsaData;                       // When WSAStartup() is called, the startup info is stored here, such as the winsock version etc
    SOCKET ListenSocket = INVALID_SOCKET;  // Receives a numeric value handled by winsock
                                           // It starts as invalid because it has not been initiated yet
    SOCKET ClientSocket = INVALID_SOCKET;  // The same happens here. This is the socket that manages the connection
    struct addrinfo *result = NULL, hints; // Stores info to be used when getaddrinfo() is called.
                                           // Result = NULL --> Will contain resolved addresses for binding/listening
                                           // hints --> instructions about how to handle the address
                                           // More about addrinfo here: https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-addrinfoa

    /**
     * INITIALIZATION
     * Here WSAStartup() is called, marking the initialization so the socket starts listening later (after some other steps)
     * If 0 then good, otherwise the program exits with an error
     */
    int iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        printf("[!] WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints)); // Initializes all hint fields to zero

    /**
     * HINTS FLAGS
     */
    hints.ai_family = AF_UNSPEC;     // The connection must accept both IPV4 and IPV6 address families
    hints.ai_socktype = SOCK_STREAM; // This is a TCP connection, so it must have a TCP socket (stream)
    hints.ai_protocol = IPPROTO_TCP; // Uses TCP protocol
    hints.ai_flags = AI_PASSIVE;     // Binds to wildcard address (all interfaces)

    /**
     * SET UP SERVER BINDING PARAMETERS
     */
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result); // NULL = uses default IP
    if (iResult != 0)
    {
        printf("[!] getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    /**
     * SET UP LISTENING SOCKET
     * Uses the result content that was filled in the previous step
     */
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET)
    {
        printf("[!] socket creation failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    /**
     * CONFIGURE DUAL-STACK CONNECTION
     * Disables IPV6_V6ONLY to allow dual-stack (IPv4+IPv6)
     */
    if (result->ai_family == AF_INET6)
    {
        int ipv6only = 0; // Enables dual-stack
        if (setsockopt(ListenSocket, IPPROTO_IPV6, 27,
                       (char *)&ipv6only, sizeof(ipv6only)) == SOCKET_ERROR)
        {
            printf("[!] Warning: Failed to set dual-stack: %d\n", WSAGetLastError());
        }
    }

    /**
     * BIND LISTENSOCKET TO THE ADDRESS SET UP BY GETADDRINFO()
     */
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR)
    {
        printf("[!] bind failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result); // Releases all address info to prevent memory leaks

    /**
     * INITIALIZE LISTENING SOCKET
     */
    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR)
    {
        printf("[!] listen failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    printf("[+] Server listening on port %s...\n", DEFAULT_PORT);
    printf("[*] Ready to accept connections\n");

    while (1)
    {
        ClientSocket = accept(ListenSocket, NULL, NULL); // NULL points out that there's no need to store client's IP:PORT
        if (ClientSocket == INVALID_SOCKET)
        {
            printf("[!] accept failed: %d\n", WSAGetLastError());
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }

        printf("[+] New connection accepted\n");
        handle_client(ClientSocket); // Calls handle_client function
    }

    closesocket(ListenSocket);
    WSACleanup();
    printf("[*] Server shutdown complete\n");

    return 0;
}
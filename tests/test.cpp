#include <bits/stdc++.h>
using namespace std;

#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <iostream>        // For std::cerr
#include <cstring>         // For strerror
#include <sys/socket.h>    // For socket functions
#include <arpa/inet.h>     // For inet_pton and sockaddr_in
#include <unistd.h>        // For close function
#include <fcntl.h>         // For fcntl
#include <sys/select.h>    // For select function and fd_set
#include <errno.h>         // For errno
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <netdb.h>
#include <regex> 
#include <fcntl.h>
#include <cstdlib>

bool is_valid_ip(const std::string& str) {
    if (str.empty()) return false;

    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;

    if (inet_pton(AF_INET, str.c_str(), &(sa.sin_addr)) == 1) {
        return true;
    }


    return false;
}

    // 解析域名为 IP 地址
int resolve_hostname(const std::string& hostname, std::string& ans) {
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET6 for IPv6, AF_INET for IPv4
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname.c_str(), NULL, &hints, &res)) != 0) {
        
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        std::string ipver;

        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        std::string ip_address(ipstr);

        freeaddrinfo(res); // Free the linked list
        ans = ip_address;
        return 1;
    }

    freeaddrinfo(res); // Free the linked list
    return 0;
}

int parse_url(const std::string &url, std::string &host, std::string &port, std::string &path) {
    // 使用正则表达式解析 URL
    std::regex url_regex(R"(^(\w+):\/\/([^\/:]+)(:(\d+))?\/?(.*)$)");
    std::smatch url_match_result;

    if (std::regex_match(url, url_match_result, url_regex)) {
        std::string protocol = url_match_result[1];
        host = url_match_result[2];
        port = url_match_result[4];  // 可选的端口号
        path = url_match_result[5];
        if (path.size() && path[0] != '/') path = '/' + path;
        else if (path.empty()) path = '/';
        // 如果没有指定端口，根据协议设置默认端口
        if (port.empty()) {
            if (protocol == "https") {
                port = "443";
            } else if (protocol == "http") {
                port = "80";
            } else {
                port = "80";
            }
        }
    } else {
        return -1;
    }
    return 0;
}

int create_socket(const std::string& address, int port) {
        struct sockaddr_in server_addr;

        // 创建 socket
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            return -1;
        }

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);

        // 解析 IP 地址或域名
        std::string ip_address;
        if (is_valid_ip(address)) {
            ip_address = address;
        } else {
            int ret = resolve_hostname(address, ip_address);
            if (ret <= 0 || ip_address.empty()) {
                
                return -1;
            }
        }


        // 将 IP 地址转换为网络字节序
        if (inet_pton(AF_INET, ip_address.c_str(), &server_addr.sin_addr) <= 0) {
            return -1;
        }
        std::cerr << "ip_address " << ip_address << std::endl;

        //  非阻塞IO
        fcntl(sockfd, F_SETFL, O_NONBLOCK);

            // Start connection attempt
        int result = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
        if (result < 0) {
        
            if (errno != EINPROGRESS) {
                return -1; // Immediate failure
            }

            fd_set write_fds;
            fd_set error_fds;
            struct timeval tv;

            FD_ZERO(&write_fds);
            FD_ZERO(&error_fds);
            FD_SET(sockfd, &write_fds);
            FD_SET(sockfd, &error_fds);

            tv.tv_sec = 10;
            tv.tv_usec = 0;

            // Wait for socket to be ready or timeout
            result = select(sockfd + 1, nullptr, &write_fds, &error_fds, &tv);

            if (result == 0) {
                // Timeout
                return -2;
            } else if (result < 0) {
                // Error
                return -1;
            }

            if (FD_ISSET(sockfd, &error_fds)) {
                // Error during connection
                return -1;
            }
        }
        return sockfd;
    }

int uy_sslconnect_until(int fd, SSL *ssl)
    {
        fd_set rset, wset, eset;
        int err, sslerr;
        struct timeval tv;

        FD_ZERO(&rset);
        FD_ZERO(&wset);
        FD_ZERO(&eset);

        while (true) {
            err = SSL_connect(ssl);
            if (err > 0)
                return 0;
            sslerr = SSL_get_error(ssl, err);
        
            switch (sslerr) {
                case SSL_ERROR_WANT_READ:
//                     FD_CLR(fd, &wset);
//                     FD_SET(fd, &rset); 
//                     FD_SET(fd, &eset);
                    break;

                case SSL_ERROR_WANT_WRITE:
                    FD_CLR(fd, &rset);
                    FD_SET(fd, &wset);
                    FD_SET(fd, &eset);
                    break;

                default:
                    return -1;
            }
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            err = select(fd + 1, &rset, &wset, &eset, &tv);
            if (err < 0) {
                return -1;
            }
        }

        return 0;
    }

struct HttpResponse {
    int statusCode;
    long long bodySize;
};

void parse_http_response(const std::string& response, HttpResponse& res, bool is_signal) {
        // Split response into headers and body
        std::size_t header_end_pos = response.find("\r\n\r\n");
        if (header_end_pos == std::string::npos) {
            return;
        }

        std::string content, stateCode, cookies;
        int bodySize = -1;

        std::string headers = response.substr(0, header_end_pos);



        content = response.substr(header_end_pos + 4); // Body starts after "\r\n\r\n"

        // Extract status code
        std::istringstream header_stream(headers);
        std::string status_line;
        std::getline(header_stream, status_line);
        std::istringstream status_line_stream(status_line);
        std::string http_version;
        std::string status_code;
        status_line_stream >> http_version >> status_code;

        stateCode = status_code;




        auto findIgnoreCase = [](const std::string& a, const std::string& b)->size_t{
            std::string ta = a;
            std::transform(ta.begin(), ta.end(), ta.begin(), ::tolower);
            return ta.find(b);
        };

        // Extract cookies
        cookies.clear();
        std::string header_line;
        while (std::getline(header_stream, header_line)) {
//          std::transform(header_line.begin(), header_line.end(), header_line.begin(), ::tolower);
            if (header_line.size() > 11 && findIgnoreCase(header_line.substr(0, 11), "set-cookie:") != std::string::npos) {
                cookies += header_line.substr(11) + "\n"; // Extract cookie value
            } else if (header_line.size() > 15 && findIgnoreCase(header_line.substr(0, 15), "content-length:") != std::string::npos) {
                std::string length_str = header_line.substr(15);
                try {
                    bodySize = std::stoi(length_str);
                } catch (const std::invalid_argument& e) {
                    // Handle error if conversion fails
                    if (is_signal) {
                    }
                    return;
                }
            }
        }





        // Clean up any trailing newline characters
        if (!cookies.empty()) {
            cookies.pop_back(); // Remove the last newline character
        }


        try {
            res.statusCode = std::stoi(stateCode);
        } catch (...) {

            if (is_signal) {

            }
            return;
        }
        res.bodySize = bodySize;
#ifdef __USE_DEBUG__
        std::cerr << "cookies: " << cookies << std::endl << "bodySize: " << bodySize << std::endl;
#endif
    }


long long ssl_read(SSL *ssl, std::string &res, int timeout_sec) {
        long long bytes_read = 0;
        size_t buffer_size = 16384; // 使用固定大小的缓冲区

        std::vector<char> buffer(buffer_size); // 16 KB 缓冲区

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(SSL_get_fd(ssl), &read_fds);

        auto start_time = std::chrono::steady_clock::now();
        auto timeout = std::chrono::seconds(timeout_sec);
        bool first_read = true;
        long long totalRead = 0;
        long long bodyRead = 0;

        while (true) {
            // 使用 select 进行超时控制
            fd_set tmp_fds = read_fds;
            struct timeval tv;
            auto now = std::chrono::steady_clock::now();
            auto elapsed = now - start_time;
            auto remaining = timeout - elapsed;

            if (remaining <= std::chrono::seconds(0)) {
            std::cerr << "Timeout reached" << std::endl;

                return -1;
            }


            tv.tv_sec = 1;
            tv.tv_usec = 0;
            std::cerr << "SSL_get_fd(ssl): " << SSL_get_fd(ssl) << std::endl;
            int select_result = select(SSL_get_fd(ssl) + 1, &tmp_fds, NULL, NULL, &tv);
            if (select_result < 0) {
                // 处理错误
                std::cerr << "select error: " << strerror(errno) << std::endl;
                return -1;
            } else if (select_result == 0) {
                // 超时
                std::cerr << "select timeout" << std::endl;

                continue;
            }

            int result = SSL_read(ssl, buffer.data(), buffer_size);
            if (result > 0) {

                start_time = std::chrono::steady_clock::now();
                std::string recv_data(buffer.begin(), buffer.begin() + result);
                HttpResponse temp = {};
                if (first_read) {// http header must be less 16kb
                    std::cerr << "first recv_data: " << std::endl << recv_data << std::endl << std::endl;
                    parse_http_response(recv_data, temp, false);
                    assert(temp.bodySize >= 0);
                    totalRead = temp.bodySize;
                } else {
                    bodyRead += result;
                }

                // 将读取到的数据附加到 res 字符串
//                res.append(recv_data, result);
                res += recv_data;
                bytes_read += result;
                if (totalRead <= bodyRead) {
                    return bytes_read;
                }
                first_read = false;
            }
            int err = SSL_get_error(ssl, result);

            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_NONE) {
                return -1;
            }
        }
        return bytes_read;
    }

void func1() {
    std::string url = "https://www.baidu.com";
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    
    // TODO no prase ipv6 
    std::string host, port, path;
    if (parse_url(url, host, port, path) < 0) {
        
        return;
    }

    try {
        int value = std::stoi(port);
    } catch (...) {
        return;
    }
    std::cerr << "host: " << host << " " << "port: " << port << std::endl;
    
// Create and connect the socket
    int sockfd = create_socket(host, std::stoi(port));
    if (sockfd < 0) {
        return;
    }    
    std::cerr << "create socket success" << std::endl;
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |  SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    // SSL_CTX_set_cipher_list(ctx, "ALL:!ECDHE-SM4-SM3:!ECC-SM1-SM3:!ECDHE-SM1-SM3"); // ECC-SM4-SM3  ALL:!ECDHE-SM4-SM3:!ECC-SM1-SM3:!ECDHE-SM1-SM3
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    int ret = uy_sslconnect_until(sockfd, ssl); // 调用 SSL_connect
    if (ret < 0) {
        int err = SSL_get_error(ssl, ret);
        const char* errorString = ERR_error_string(ERR_get_error(), nullptr);
        
        std::cerr << "SSL_get_error: " << errorString << std::endl;
    } else {
        
        std::string requestHeadFmtStr = 
        "%s %s HTTP/1.1\r\n"
        "Content-Type: application/json;charset=\"UTF-8\"\r\n"
        "User-Agent: linux\r\n"
        "Host: %s:%d\r\n"
        "Cookie: %s\r\n"
        "Content-Length: %d\r\n\r\n%s";

    // 构建 HTTP 请求
    std::string ip = host;
    char buffer_send[1024];
    snprintf(buffer_send, sizeof(buffer_send), requestHeadFmtStr.c_str(), 
             "GET", "/", ip.c_str(), 443, "", 0, "");
        SSL_write(ssl, buffer_send, strlen(buffer_send));

        std::string res;
        ssl_read(ssl, res, 10);
    }

    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}

    
int main() {
    func1();
    return 0;
    std::future<void> t1 = std::async(std::launch::async, &func1);
    t1.get();
    
    return 0;
}
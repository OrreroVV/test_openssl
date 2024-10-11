#include "create_tun.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>

TunDevice::TunDevice(const std::string& devName) : dev(devName), fd(-1) {}

TunDevice::~TunDevice() {
    if (fd > 0) {
        close(fd);
    }
}

int TunDevice::createTunDevice(int flags) {
    struct ifreq ifr;
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("Opening /dev/net/tun");
        return -1; // 返回错误码
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags; // 设置标志
    strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);

    // 创建 TUN 设备
    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1; // 返回错误码
    }

    printf("TUN device %s created successfully\n", ifr.ifr_name); // 打印成功消息
    return 0; // 成功
}


void TunDevice::configureTunDevice(const char *ip, const char *netmask) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Creating socket to configure TUN device");
        return;
    }

    // 检查现有的 IP 地址
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);

    // 尝试获取当前的 IP 地址
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) {
        printf("TUN device %s already has an IP address\n", dev.c_str());
    } else {
        // 设置 IP 地址
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
        addr->sin_family = AF_INET;
        inet_pton(AF_INET, ip, &addr->sin_addr);

        if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
            perror("ioctl(SIOCSIFADDR)");
        } else {
            printf("IP address %s set for TUN device %s\n", ip, dev.c_str());
        }
    }

    // 配置 IP 地址
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR)");
        close(sockfd);
        return;
    }

    // 配置子网掩码
    inet_pton(AF_INET, netmask, &addr->sin_addr);
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK)");
        close(sockfd);
        return;
    }

    // 启动 TUN 设备
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCGIFFLAGS)");
    } else {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
            perror("ioctl(SIOCSIFFLAGS)");
        }
    }

    close(sockfd);
    std::cout << "TUN device configured successfully" << std::endl;
}


// 添加路由
void TunDevice::addRoute(const char *dest) {
    char cmd[100];
    snprintf(cmd, sizeof(cmd), "ip route add %s dev %s", dest, dev.c_str());
    system(cmd);
}
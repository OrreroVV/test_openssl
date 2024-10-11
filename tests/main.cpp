#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <cstring>
#include "code/create_tun.h"

int main() {
    // 创建一个 TUN 设备实例
    TunDevice tun("tun0");

    // 创建 TUN 设备，使用 IFF_TUN 标志（仅隧道接口，不带以太网头）
    if (tun.createTunDevice(IFF_TUN | IFF_NO_PI) < 0) {
        std::cerr << "Failed to create TUN device" << std::endl;
        return 1;
    }

    // 配置 TUN 设备的 IP 和子网掩码
    tun.configureTunDevice("10.0.0.1", "255.255.255.0");

    // 添加路由
    tun.addRoute("10.0.0.0/24");


    return 0;
}

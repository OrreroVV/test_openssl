#ifndef __CREATE_TUN_H__
#define __CREATE_TUN_H__

#include <string>

class TunDevice {
public:
    TunDevice(const std::string& devName);
    ~TunDevice();
    
    int createTunDevice(int flags);                // 创建 TUN 设备
    void configureTunDevice(const char *ip, const char *netmask);  // 配置 TUN 设备
    void addRoute(const char *dest);               // 添加路由

    std::string dev;   // TUN 设备名称
    int fd;            // TUN 设备的文件描述符

private:

};

#endif
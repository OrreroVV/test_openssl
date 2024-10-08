cmake_minimum_required(VERSION 3.8)

project(test)

# 设置 C++17 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)



# 公共编译选项
add_compile_options(
    -Wall 
    -Werror 
    -Wno-deprecated 
    -Wno-unused-function 
    -Wno-builtin-macro-redefined 
    -Wno-deprecated-declarations 
    -Wno-unused-variable
    -Werror=sign-compare
    -Wno-error=address
)


# 手动设置 JDK 8 路径
set(JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64)
set(JAVA_INCLUDE_DIRS ${JAVA_HOME}/include)
set(JAVA_INCLUDE_DIRS2 ${JAVA_HOME}/include/linux)

# 查找 JNI 库
find_package(JNI REQUIRED)
include_directories(${JAVA_INCLUDE_DIRS} ${JAVA_INCLUDE_DIRS2} ${JNI_INCLUDE_DIRS})

# 查找 JNI 库
find_package(JNI REQUIRED)
include_directories(${JAVA_INCLUDE_DIRS})


include_directories(.)

set(LIB_SRC
    code/model.cpp
    code/thread.cpp
    code/util.cpp
    code/Demo.cpp
    code/httpgmssl.cpp
    )

add_library(hzh SHARED ${LIB_SRC})

# 设置库的输出名称
set_target_properties(hzh PROPERTIES OUTPUT_NAME "hzh")


find_package(OpenSSL REQUIRED)


set(LIB_LIB
    hzh 
    -dl
    -lssl
    -lcrypto
    -lpthread
)


add_executable(server tests/openssl_server.cpp)
add_dependencies(server hzh)
target_link_libraries(server ${LIB_LIB})


add_executable(client tests/openssl_client.cpp)
add_dependencies(client hzh)
target_link_libraries(client ${LIB_LIB})


SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
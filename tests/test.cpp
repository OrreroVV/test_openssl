#include <bits/stdc++.h>
#include "code/httpgmssl.h"
using namespace std;

struct Output
{
    int a, b;
};

Output func1(int x, int y) {
    string res;
    ssl_send_data_request("", "", HttpType::GET, "", &res);
    return { x, y };
}
    
int main() {

    
    std::future<Output> t1 = std::async(std::launch::async, &func1, 3, 5);
    t1.get();
    
    return 0;
}
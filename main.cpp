#include "big_int/big_int.hpp"

int main()
{
    std::string str1 = "40";
    std::string str2 = "20";
    BigInt a(str1);
    BigInt b(str2);
    BigInt c = (a << 64) + b;
    std::cout << "Result: " << std::hex << c << std::endl;
    BigInt r = c % a;
    std::cout << "c % a = " << std::hex << r << std::endl;
    return 0;
}

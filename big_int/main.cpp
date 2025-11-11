#include "big_int.hpp"

int main() {
    BigInt num1, num2;
    int c = 1;
    do {
        std::cin >> num1 >> num2;
        std::cout << num1 + num2 << std::endl;
    } while (c);

    return 0;
}
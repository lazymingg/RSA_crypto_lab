#include "big_int.hpp"

int main() {
    BigInt limit;

    std::cout << "MAX = ";
    std::cin >> limit;

    for (int i = 0; i < 20; i++) {
        BigInt temp = BigInt::randomBase(limit);

        if (temp > limit - BigInt(2)) {
            std::cout << temp.to_string() << " failed " << std::endl; 
        }

        else {
            std::cout << temp.to_string() << std::endl;
        }
    }

    return 0;
}
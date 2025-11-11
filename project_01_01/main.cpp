#include "../big_int/big_int.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>

const int smallPrimes[10] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29};

// (x * y) % n
BigInt mulMod(BigInt x, BigInt y, BigInt n) {
    x %= n;
    BigInt p = 0;

    if (y > 0) {
        p = x;
    }

    int len =  y.getBitLen();
    
    for (int i = 1; i < len; i++) {
        x = x * 2 % n;
        
        if (y.getBit(i)) {
            if (p > n) {
                p = p - n;
            }

            p = (p + x) % n;
        }
    }

    return p;
}

// x^p % n
BigInt powerMod(BigInt x, BigInt p, BigInt n) {
    BigInt y = 1;
    BigInt temp = x;

    if (p == 0) {
        y = x;
    }

    int len = p.getBitLen();

    for (int i = 0; i < len; i++) {
        temp = mulMod(temp, temp, n);

        if (p.getBit(i)) {
            y = (temp * y) % n;
        }
    }

    return y;
}

bool millerRabin(BigInt n) {
    if (n < 2) {
        return false;
    }

    if (n % 2 == 0) {
        return false;
    }

    // n - 1 = 2^r * m
    BigInt m = n - 1;
    int r = 0;

    while (m % 2 == 0) {
        m = m / 2;
        r++;
    }

    for (int i = 0; i < r; i++) {
        int randIdx = random() % 10;
        
        // 2^i * m
        BigInt pow = m * powerMod(BigInt(2), BigInt(i), n);
        
        if (powerMod(smallPrimes[randIdx], pow, n) != 1 && powerMod(smallPrimes[randIdx], pow, n) != -1) {
            return false;
        }
    }

    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>\n";
        return 1;
    }

    std::ifstream in(argv[1]);

    if (!in) {
        std::cerr << "Error opening file: " << argv[1] << std::endl;
        return 1;
    }

    std::string num;
    getline(in, num);
    std::reverse(num.begin(), num.end());

    BigInt p = BigInt(num);

    if (millerRabin(p)) {
        std::cout << argv[1] << " passed" << std::endl;
    }

    else {
        std::cout << argv[1] << " failed" << std::endl;
    }
}
#include "../big_int/big_int.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>

// (x * y) % n
BigInt mulMod(BigInt x, BigInt y, BigInt n) {
    x %= n;
    BigInt p = BigInt(0);

    int len = y.getBitLen();
    for (int i = 0; i < len; ++i) {
        if (y.getBit(i)) {
            p = p + x;
            
            if (p >= n) {
                p = p - n;
            }
        }

        x = x << 1;
        
        if (x >= n) {
            x = x - n;
        }
    }

    return p % n;
}

// x^p % n
BigInt powerMod(BigInt x, BigInt p, BigInt n) {
    BigInt result = BigInt(1);

    int len = p.getBitLen();
    
    for (int i = 0; i < len; ++i) {
        if (p.getBit(i)) {
            result = mulMod(result, x, n);
        }

        x = mulMod(x, x, n);
    }

    return result;
}

bool millerRabin(BigInt n, int k = 10) {
    if (n < 2 || !n.is_odd()) {
        return false;   
    }

    // n - 1 = 2^r * m
    BigInt m = n - BigInt(1);
    int r = 0;
    
    while (!m.is_odd()) {
        m = m >> 1;
        r++;
    }

    for (int i = 0; i < k; i++) {
        BigInt a = BigInt::randomBase(n);

        // a in [2, n - 2]
        if (a >= n - BigInt(2)) {
            a = BigInt(2);   
        }

        BigInt x = powerMod(a, m, n);
        
        // a^m % n == +- 1
        if (x == BigInt(1) || x == (n - BigInt(1))) {
            continue;
        }

        bool composite = true;

        for (int j = 1; j < r; ++j) {
            x = mulMod(x, x, n);
            
            // x^2 % n == -1
            if (x == (n - BigInt(1))) {
                composite = false;
                break;
            }
        }

        if (composite) {
            return false;
        }
    }

    return true;
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file>.inp <output_file>.out\n";
        return 1;
    }

    std::ifstream in(argv[1]);

    if (!in) {
        std::cerr << "Error opening file: " << argv[1] << std::endl;
        return 1;
    }

    std::ofstream out(argv[2]);

    if (!out) {
        std::cerr << "Error writing file: " << argv[2] << std::endl;

        return 1;
    }

    std::string num;
    getline(in, num);
    std::reverse(num.begin(), num.end());

    BigInt p = BigInt(num);

    if (millerRabin(p)) {
        out << 1 << std::endl;
    }

    else {
        out << 0 << std::endl;
    }

}
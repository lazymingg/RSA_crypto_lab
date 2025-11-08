#include "../big_int/big_int.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>
using namespace std;

BigInt powmod(BigInt a, BigInt b, const BigInt &mod) {
    BigInt result(1);
    BigInt zero(0);
    BigInt two(2);

    while (!b.is_zero()) {
        if (b.is_odd()) result = (result * a) % mod;
        a = (a * a) % mod;
        b = b >> 1;
    }
    return result;
}

bool checkPrime(const BigInt &n) {
    BigInt zero(0), one(1), two(2);

    if (n <= two) return n == two;  
    if ((n % two).is_zero()) return false; 

    BigInt d = n - one;
    int s = 0;
    while ((d % two).is_zero()) {
        d = d / two;
        s++;
    }

    BigInt bases[] = {BigInt(2), BigInt(3), BigInt(5), BigInt(7), BigInt(11)};
    for (int i = 0; i < 5; i++) {
        BigInt a = bases[i];
        if (a >= n - one) continue;

        BigInt x = powmod(a, d, n);
        if (x == one || x == n - one) continue;

        bool found = false;
        for (int r = 1; r < s; r++) {
            x = (x * x) % n;
            if (x == n - one) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }

    return true; 
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <input_file>\n";
        return 1;
    }

    ifstream ifile(argv[1]);
    if (!ifile.is_open()) {
        cerr << "Error opening file: " << argv[1] << endl;
        return 1;
    }

    string line;
    getline(ifile, line);

    reverse(line.begin(), line.end());


    // tạo BigInt từ chuỗi hex
    BigInt num(line);
    cout << "Number: " << num << endl;

    if (checkPrime(num))
        cout << "1\n";
    else
        cout << "0\n";

    return 0;
}
#include "../big_int/big_int.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>
using namespace std;

BigInt extended_gcd(const BigInt &a, const BigInt &b, BigInt &x, BigInt &y)
{
    BigInt zero = 0;
    BigInt one = 1;

    if (b == zero)
    {
        x = one;
        y = zero;
        return a;
    }

    BigInt x1, y1;
    BigInt val_gcd = extended_gcd(b, a % b, x1, y1);

    x = y1; 
    y = x1 - (a / b) * y1;

    return val_gcd;
}

BigInt modInverse(const BigInt &a, const BigInt &b)
{
    BigInt x, y;
    BigInt val_gcd = extended_gcd(a, b, x, y);

    if(val_gcd != BigInt(1)){
        return BigInt(0);
    }

    x = (x + b) % b;

    return x;
}


BigInt genKey(const BigInt &p, const BigInt &q, const BigInt &e)
{
    BigInt one = 1;
    BigInt phi = (p - one) * (q - one);
    BigInt d = modInverse(e, phi);

    return d;
}

int main(int argc, char* argv[])
{
    // testing_mode();
    // return 0;
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <input_file>\n";
        return 1;
    }

    // cout << "Program name: " << argv[0] << endl;
    // cout << "Input file: " << argv[1] << endl;
    ifstream ifile(argv[1]);

    if (!ifile.is_open()) {
        cerr << "Error opening file: " << argv[1] << endl;
        return 1;
    }

    string p_str;
    string q_str;
    string e_str;

    getline(ifile, p_str);
    getline(ifile, q_str);
    getline(ifile, e_str);

    // đảo ngược chuỗi 
    reverse(p_str.begin(), p_str.end());
    reverse(q_str.begin(), q_str.end());
    reverse(e_str.begin(), e_str.end());

    BigInt p_num(p_str);
    BigInt q_num(q_str);
    BigInt e_num(e_str);

    
    cout << p_num << endl;
    cout << q_num << endl;
    cout << e_num << endl;

    BigInt d = genKey(p_num, q_num, e_num);
    if(d == BigInt(0))
    {
        string output = "-1";
        cout << output << endl;
    }
    else 
    {
        string output = d.to_string();
        // cout << output << endl;
        reverse(output.begin(), output.end());

        cout << output << endl;
    }
    return 0;
}
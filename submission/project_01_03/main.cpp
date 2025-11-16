#include "../big_int/big_int.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>

using namespace std;


BigInt mod_exp(BigInt base, BigInt exponent, const BigInt &modulus)
{
    BigInt result(1);
    base = base % modulus;

    while (!(exponent == BigInt(0)))
    {

        if ((exponent.data[0] & 1) != 0)
            result = (result * base) % modulus;

        base = (base * base) % modulus;

        exponent = exponent >> 1;
    }

    return result;
}


BigInt RSA_encrypt(const BigInt &message, const BigInt &e, const BigInt &n)
{
    return mod_exp(message, e, n);
}

BigInt RSA_decrypt(const BigInt &ciphertext, const BigInt &d, const BigInt &n)
{
    return mod_exp(ciphertext, d, n);
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <input_file>.inp <output_file>.out\n";
        return 1;
    }

    ifstream ifile(argv[1]);

    if (!ifile.is_open()) {
        cerr << "Error opening file: " << argv[1] << endl;
        return 1;
    }

    ofstream ofile(argv[2]);

    if (!ofile.is_open()) {
        cerr << "Error opening file: " << argv[2] << endl;
    }

    string modulus_str;
    string exponent_str;
    string message_str;

    getline(ifile, modulus_str);
    getline(ifile, exponent_str);
    getline(ifile, message_str);

    // đảo ngược chuỗi 
    reverse(modulus_str.begin(), modulus_str.end());
    reverse(exponent_str.begin(), exponent_str.end());
    reverse(message_str.begin(), message_str.end());

    BigInt modulus(modulus_str);
    BigInt exponent(exponent_str);
    BigInt message(message_str);

    BigInt ciphertext = RSA_encrypt(message, exponent, modulus);
    string output = ciphertext.to_string();
    reverse(output.begin(), output.end());

    // upper case
    transform(output.begin(), output.end(), output.begin(), ::toupper);
    ofile << output << endl;
    
    ifile.close();
    ofile.close();

    return 0;
}

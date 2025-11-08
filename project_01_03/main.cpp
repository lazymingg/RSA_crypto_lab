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

// void testing_mode()
// {
//     string dir = "./project_01_03/";
//     int test_cases = 19;
//     for (int i = 0; i < test_cases; i++)
//     {
//         ifstream ifile(dir + "test_" + (i < 10 ? "0" : "") + to_string(i) + ".inp");
//         string modulus_str;
//         string exponent_str;
//         string message_str;

//         getline(ifile, modulus_str);
//         getline(ifile, exponent_str);
//         getline(ifile, message_str);

//         reverse(modulus_str.begin(), modulus_str.end());
//         reverse(exponent_str.begin(), exponent_str.end());
//         reverse(message_str.begin(), message_str.end());

//         BigInt modulus(modulus_str);
//         BigInt exponent(exponent_str);
//         BigInt message(message_str);
//         BigInt ciphertext = RSA_encrypt(message, exponent, modulus);

//         string output = ciphertext.to_string();
//         reverse(output.begin(), output.end());
//         // convert to uppercase
//         transform(output.begin(), output.end(), output.begin(), ::toupper);

//         ifstream ofile(dir + "test_0" + to_string(i) + ".out");
//         string expected_output;
//         getline(ofile, expected_output);
        
//         cout << "Test case " << i << ": ";
//         cout << "Modulus: " << modulus_str << ", Exponent: " << exponent_str << ", Message: " << message_str << endl;
//         cout << (output == expected_output ? "Passed" : "Failed") << endl;
//         cout << "Expected: " << expected_output << endl;
//         cout << "Got     : " << output << endl;
//         cout << endl;
//         ifile.close();
//         ofile.close();
//     }
// }

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

    // Example usage
    BigInt ciphertext = RSA_encrypt(message, exponent, modulus);
    string output = ciphertext.to_string();
    reverse(output.begin(), output.end());
    // cout << "Modulus: " << modulus << endl;
    // cout << "Exponent: " << exponent << endl;
    // cout << "Original message: " << message << endl;
    // string output = ciphertext.to_string();
    // reverse(output.begin(), output.end());
    // cout << "Ciphertext or Decrypt Message: " << output << endl;
    cout << output << endl;

    return 0;
}

// Header-only BigInt (2048-bit) library
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstring>

class BigInt
{

    public:
    uint32_t data[64] = {0}; // 64 * 32 = 2048 bits
    
    BigInt()
    {
        std::memset(data, 0, sizeof(data));
    }

    BigInt(const uint64_t n)
    {
        std::memset(data, 0, sizeof(data));
        data[0] = n;
        data[1] = n >> 32;
    }

    BigInt operator+(const BigInt &other) const
    {
        BigInt result;
        uint64_t carry = 0;
        for (size_t i = 0; i < 64; ++i)
        {
            uint64_t sum = uint64_t(data[i]) + uint64_t(other.data[i]) + carry;
            result.data[i] = uint32_t(sum);
            carry = sum >> 32;
        }
        return result;
    }

    bool is_zero() const
    {
        for (size_t i = 0; i < 64; ++i)
            if (data[i] != 0)
                return false;
        return true;
    }

    bool is_odd() const { return (data[0] & 1U) != 0; }

    BigInt &operator+=(const BigInt &other)
    {
        *this = *this + other;
        return *this;
    }

    BigInt operator-(const BigInt &other) const
    {
        BigInt result;
        uint64_t borrow = 0;

        for (size_t i = 0; i < 64; ++i)
        {
            uint64_t a = data[i];
            uint64_t b = other.data[i] + borrow;

            borrow = (a < b);
            result.data[i] = uint32_t(a - b);
        }

        return result;
    }

    BigInt operator*(const BigInt &other) const
    {
        BigInt result;

        for (size_t i = 0; i < 64; ++i)
        {
            uint64_t carry = 0;
            for (size_t j = 0; j + i < 64; ++j)
            {
                uint64_t mul = uint64_t(data[i]) * uint64_t(other.data[j]) + uint64_t(result.data[i + j]) + carry;
                result.data[i + j] = uint32_t(mul);
                carry = mul >> 32;
            }
        }

        return result;
    }

    BigInt operator<<(size_t shift) const
    {
        BigInt result;

        if (shift == 0)
            return *this;
        if (shift >= 2048)
            return result; // = 0

        size_t limb_shift = shift / 32;
        size_t bit_shift = shift % 32;

        for (int i = 63; i >= 0; --i)
        {
            if ((size_t)i < limb_shift)
            {
                result.data[i] = 0;
                continue;
            }

            size_t src = (size_t)i - limb_shift;

            uint64_t val = uint64_t(data[src]) << bit_shift;

            if (bit_shift && src > 0)
                val |= uint64_t(data[src - 1]) >> (32 - bit_shift);

            result.data[i] = uint32_t(val);
        }

        return result;
    }

    BigInt operator>>(size_t shift) const
    {
        BigInt result;

        if (shift == 0)
            return *this;
        if (shift >= 2048)
            return result; // = 0

        size_t limb_shift = shift / 32;
        size_t bit_shift = shift % 32;

        for (size_t i = 0; i < 64; ++i)
        {
            size_t src = i + limb_shift;
            if (src >= 64)
                continue;

            uint64_t val = uint64_t(data[src]) >> bit_shift;

            if (bit_shift && src + 1 < 64)
                val |= uint64_t(data[src + 1]) << (32 - bit_shift);

            result.data[i] = uint32_t(val);
        }

        return result;
    }

    bool operator<(const BigInt &other) const
    {
        for (int i = 63; i >= 0; --i)
        {
            if (data[i] < other.data[i])
                return true;
            if (data[i] > other.data[i])
                return false;
        }
        return false;
    }
    bool operator>(const BigInt &other) const { return other < *this; }

    bool operator>=(const BigInt &other) const
    {
        for (int i = 63; i >= 0; --i)
        {
            if (data[i] > other.data[i])
                return true;
            else if (data[i] < other.data[i])
                return false;
        }
        return true;
    }

    bool operator<=(const BigInt &other) const
    {
        for (int i = 63; i >= 0; --i)
        {
            if (data[i] > other.data[i])
                return false;
            if (data[i] < other.data[i])
                return true;
        }
        return true;
    }

    BigInt operator/(const BigInt &other) const
    {
        BigInt quotient;
        BigInt remainder;

        for (int bit = 2047; bit >= 0; --bit)
        {
            remainder = remainder << 1;

            size_t limb_index = bit / 32;
            size_t bit_index = bit % 32;
            uint32_t bit_value = (data[limb_index] >> bit_index) & 1U;
            remainder.data[0] |= bit_value;

            if (remainder >= other)
            {
                remainder = remainder - other;

                size_t q_limb = bit / 32;
                size_t q_bit = bit % 32;
                quotient.data[q_limb] |= (1U << q_bit);
            }
        }

        return quotient;
    }

    BigInt operator%(const BigInt &other) const
    {
        BigInt remainder;

        for (int bit = 2047; bit >= 0; --bit)
        {
            remainder = remainder << 1;

            size_t limb_index = bit / 32;
            size_t bit_index = bit % 32;
            uint32_t bit_value = (data[limb_index] >> bit_index) & 1U;
            remainder.data[0] |= bit_value;

            if (remainder >= other)
            {
                remainder = remainder - other;
            }
        }

        return remainder;
    }

    BigInt &operator%=(const BigInt &other)
    {
        *this = *this % other;
        return *this;
    }

    // constructor for big int from big endian string
    BigInt(const std::string &str)
    {

        std::memset(data, 0, sizeof(data));

        int len = str.length();
        int limb = 0;
        for (int pos = len; pos > 0 && limb < 64; pos -= 8, ++limb)
        {
            int start = std::max(0, pos - 8);
            std::string chunk = str.substr(start, pos - start);

            data[limb] = std::stoul(chunk, nullptr, 16);
        }
    }

    friend std::ostream &operator<<(std::ostream &os, const BigInt &bigInt)
    {
        // Save and restore stream state
        std::ios_base::fmtflags f = os.flags();
        char old_fill = os.fill();

        os << std::hex << std::setfill('0');

        int i = 63;
        while (i > 0 && bigInt.data[i] == 0)
            --i;

        os << std::hex << bigInt.data[i];

        for (--i; i >= 0; --i)
            os << std::setw(8) << bigInt.data[i];

        os.flags(f);
        os.fill(old_fill);
        return os;
    }
    
    friend std::istream &operator>>(std::istream &is, BigInt &bigInt)
    {
        std::string str;
        is >> str;
        bigInt = BigInt(str);
        return is;
    }

    bool operator==(const BigInt &other) const
    {
        for (int i = 0; i < 64; ++i)
            if (data[i] != other.data[i])
                return false;
        return true;
    }

    bool operator!=(const BigInt &other) const
    {
        return !(*this == other);
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << std::hex << *this;
        return oss.str();
    }
};

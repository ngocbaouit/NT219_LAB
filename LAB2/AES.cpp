#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <stdint.h>
#include <stdexcept>
#include <bitset>
#include <sstream>
#include <iomanip>
#include <locale>
#include <codecvt>

#ifdef _WIN32
#include <windows.h>
#endif

class AES
{
private:
    std::vector<std::vector<uint8_t>> round_keys;
    std::vector<uint8_t> key;
    uint8_t key_length;

    std::vector<uint8_t> S_BOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
    std::vector<uint8_t> INV_S_BOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

    std::vector<std::vector<uint8_t>> RCON = {
        {0x01, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00},
        {0x08, 0x00, 0x00, 0x00},
        {0x10, 0x00, 0x00, 0x00},
        {0x20, 0x00, 0x00, 0x00},
        {0x40, 0x00, 0x00, 0x00},
        {0x80, 0x00, 0x00, 0x00},
        {0x1B, 0x00, 0x00, 0x00},
        {0x36, 0x00, 0x00, 0x00}};

    std::vector<uint8_t> sub_word(std::vector<uint8_t> word)
    {
        std::vector<uint8_t> result;
        for (uint8_t b : word)
        {
            result.push_back(S_BOX[b]);
        }
        return result;
    }

    std::vector<uint8_t> rot_word(std::vector<uint8_t> word)
    {
        std::rotate(word.begin(), word.begin() + 1, word.end());
        return word;
    }

    std::vector<std::vector<uint8_t>> key_expansion_128()
    {
        uint8_t key_size = 16;
        uint8_t key_words = key_size / 4;
        std::vector<std::vector<uint8_t>> round_keys(key_words);
        for (uint8_t i = 0; i < key_size; i += 4)
        {
            round_keys[i / 4] = std::vector<uint8_t>(key.begin() + i, key.begin() + i + 4);
        }
        for (uint8_t i = key_words; i < 44; i++)
        {
            std::vector<uint8_t> temp = round_keys[i - 1];
            if (i % key_words == 0)
            {
                temp = sub_word(rot_word(temp));
                for (uint8_t j = 0; j < 4; j++)
                {
                    temp[j] ^= RCON[(i - key_words) / key_words][j];
                }
            }
            std::vector<uint8_t> round_key(4);
            for (uint8_t j = 0; j < 4; j++)
            {
                round_key[j] = round_keys[i - key_words][j] ^ temp[j];
            }
            round_keys.push_back(round_key);
        }
        return round_keys;
    }

    std::vector<std::vector<uint8_t>> key_expansion_192()
    {
        std::vector<std::vector<uint8_t>> round_keys;
        for (uint8_t i = 0; i < 24; i += 4)
        {
            round_keys.push_back(std::vector<uint8_t>(key.begin() + i, key.begin() + i + 4));
        }
        for (uint8_t i = 6; i < 52; i++)
        {
            std::vector<uint8_t> temp = round_keys[i - 1];
            if (i % 6 == 0)
            {
                temp = sub_word(rot_word(temp));
                for (uint8_t j = 0; j < 4; j++)
                {
                    temp[j] ^= RCON[(i - 6) / 6][j];
                }
            }
            std::vector<uint8_t> round_key(4);
            for (uint8_t j = 0; j < 4; j++)
            {
                round_key[j] = round_keys[i - 6][j] ^ temp[j];
            }
            round_keys.push_back(round_key);
        }
        return round_keys;
    }

    std::vector<std::vector<uint8_t>> key_expansion_256()
    {
        std::vector<std::vector<uint8_t>> round_keys;
        for (uint8_t i = 0; i < 32; i += 4)
        {
            round_keys.push_back(std::vector<uint8_t>(key.begin() + i, key.begin() + i + 4));
        }
        for (uint8_t i = 8; i < 60; i++)
        {
            std::vector<uint8_t> temp = round_keys[i - 1];
            if (i % 8 == 0)
            {
                temp = sub_word(rot_word(temp));
                for (uint8_t j = 0; j < 4; j++)
                {
                    temp[j] ^= RCON[(i - 8) / 8][j];
                }
            }
            else if (i % 8 == 4)
            {
                temp = sub_word(temp);
            }
            std::vector<uint8_t> round_key(4);
            for (uint8_t j = 0; j < 4; j++)
            {
                round_key[j] = round_keys[i - 8][j] ^ temp[j];
            }
            round_keys.push_back(round_key);
        }
        return round_keys;
    }

    std::vector<std::vector<uint8_t>> sub_bytes(std::vector<std::vector<uint8_t>> state)
    {
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                uint8_t row = state[i][j] / 0x10;
                uint8_t col = state[i][j] % 0x10;
                state[i][j] = S_BOX[16 * row + col];
            }
        }
        return state;
    }

    std::vector<std::vector<uint8_t>> shift_rows(std::vector<std::vector<uint8_t>> state)
    {
        std::rotate(state[1].begin(), state[1].begin() + 1, state[1].end());
        std::rotate(state[2].begin(), state[2].begin() + 2, state[2].end());
        std::rotate(state[3].begin(), state[3].begin() + 3, state[3].end());
        return state;
    }

    std::vector<std::vector<uint8_t>> mix_columns(std::vector<std::vector<uint8_t>> state)
    {
        auto gmul = [](uint8_t a, uint8_t b) -> uint8_t
        {
            uint8_t p = 0;
            for (uint8_t i = 0; i < 8; i++)
            {
                if (b & 1)
                {
                    p ^= a;
                }
                bool hi_bit_set = a & 0x80;
                a <<= 1;
                if (hi_bit_set)
                {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            return p % 256;
        };

        for (uint8_t i = 0; i < 4; i++)
        {
            std::vector<uint8_t> col(4);
            for (uint8_t j = 0; j < 4; j++)
            {
                col[j] = state[j][i];
            }
            state[0][i] = gmul(0x02, col[0]) ^ gmul(0x03, col[1]) ^ col[2] ^ col[3];
            state[1][i] = col[0] ^ gmul(0x02, col[1]) ^ gmul(0x03, col[2]) ^ col[3];
            state[2][i] = col[0] ^ col[1] ^ gmul(0x02, col[2]) ^ gmul(0x03, col[3]);
            state[3][i] = gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ gmul(0x02, col[3]);
        }

        return state;
    }

    std::vector<std::vector<uint8_t>> inv_mix_columns(std::vector<std::vector<uint8_t>> state)
    {
        auto gmul = [](uint8_t a, uint8_t b) -> uint8_t
        {
            uint8_t p = 0;
            for (uint8_t i = 0; i < 8; i++)
            {
                if (b & 1)
                {
                    p ^= a;
                }
                bool hi_bit_set = a & 0x80;
                a <<= 1;
                if (hi_bit_set)
                {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            return p % 256;
        };

        for (uint8_t i = 0; i < 4; i++)
        {
            std::vector<uint8_t> col(4);
            for (uint8_t j = 0; j < 4; j++)
            {
                col[j] = state[j][i];
            }
            state[0][i] = gmul(0x0E, col[0]) ^ gmul(0x0B, col[1]) ^ gmul(0x0D, col[2]) ^ gmul(0x09, col[3]);
            state[1][i] = gmul(0x09, col[0]) ^ gmul(0x0E, col[1]) ^ gmul(0x0B, col[2]) ^ gmul(0x0D, col[3]);
            state[2][i] = gmul(0x0D, col[0]) ^ gmul(0x09, col[1]) ^ gmul(0x0E, col[2]) ^ gmul(0x0B, col[3]);
            state[3][i] = gmul(0x0B, col[0]) ^ gmul(0x0D, col[1]) ^ gmul(0x09, col[2]) ^ gmul(0x0E, col[3]);
        }

        return state;
    }

    std::vector<std::vector<uint8_t>> add_round_key(std::vector<std::vector<uint8_t>> state, uint8_t round_number)
    {
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                state[j][i] ^= round_keys[round_number * 4 + i][j];
            }
        }
        return state;
    }

    std::vector<std::vector<uint8_t>> inv_sub_bytes(std::vector<std::vector<uint8_t>> state)
    {
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                uint8_t row = state[i][j] / 0x10;
                uint8_t col = state[i][j] % 0x10;
                state[i][j] = INV_S_BOX[16 * row + col];
            }
        }
        return state;
    }

    std::vector<std::vector<uint8_t>> inv_shift_rows(std::vector<std::vector<uint8_t>> state)
    {
        std::rotate(state[1].rbegin(), state[1].rbegin() + 1, state[1].rend());
        std::rotate(state[2].rbegin(), state[2].rbegin() + 2, state[2].rend());
        std::rotate(state[3].rbegin(), state[3].rbegin() + 3, state[3].rend());
        return state;
    }

public:
    AES(std::vector<uint8_t> key, uint8_t key_length) : key(key), key_length(key_length)
    {
        round_keys = key_expansion(key, key_length);
    }

    std::vector<std::vector<uint8_t>> key_expansion(std::vector<uint8_t> key, uint8_t length)
    {
        this->key = key;
        this->key_length = length;
        if (length == 128)
        {
            return key_expansion_128();
        }
        else if (length == 192)
        {
            return key_expansion_192();
        }
        else if (length == 256)
        {
            return key_expansion_256();
        }
        else
        {
            throw std::invalid_argument("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
        }
    }

    std::vector<uint8_t> encrypt(std::vector<uint8_t> data)
    {
        if (round_keys.empty())
        {
            round_keys = key_expansion(key, key_length);
        }

        std::vector<std::vector<uint8_t>> state(4, std::vector<uint8_t>(4));
        for (uint8_t i = 0; i < data.size(); i += 4)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                state[j][i / 4] = data[i + j];
            }
        }

        uint8_t key_length = 16;
        uint8_t num_rounds;

        switch (key_length)
        {
        case 16:
            num_rounds = 10;
            break;
        case 24:
            num_rounds = 12;
            break;
        case 32:
            num_rounds = 14;
            break;
        default:
            throw std::invalid_argument("Invalid key length");
        }

        add_round_key(state, 0);

        for (uint8_t round = 1; round < num_rounds; round++)
        {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }

        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, num_rounds);

        // Flatten the 2D state array into a 1D vector
        std::vector<uint8_t> encrypted_data(16);
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                encrypted_data[i * 4 + j] = state[j][i];
            }
        }

        return encrypted_data;
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext)
    {
        if (round_keys.empty())
        {
            round_keys = key_expansion(key, key_length);
        }

        std::vector<std::vector<uint8_t>> state(4, std::vector<uint8_t>(4));
        for (uint8_t i = 0; i < ciphertext.size(); i += 4)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                state[j][i / 4] = ciphertext[i + j];
            }
        }

        uint8_t key_length = 16;
        uint8_t num_rounds;

        switch (key_length)
        {
        case 16:
            num_rounds = 10;
            break;
        case 24:
            num_rounds = 12;
            break;
        case 32:
            num_rounds = 14;
            break;
        default:
            throw std::invalid_argument("Invalid key length");
        }

        add_round_key(state, num_rounds);

        for (uint8_t round = num_rounds - 1; round > 0; round--)
        {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, round);
            inv_mix_columns(state);
        }

        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, 0);

        // Flatten the 2D state array into a 1D vector
        std::vector<uint8_t> decrypted_data(16);
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                decrypted_data[i * 4 + j] = state[j][i];
            }
        }

        return decrypted_data;
    }
};

class Modes
{
private:
    AES aes;
    std::vector<uint8_t> iv;

public:
    Modes(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
        : aes(key, static_cast<int>(key.size() * 8)), iv(iv)
    {
        int key_length = static_cast<int>(key.size() * 8);
        if (key_length != 128 && key_length != 192 && key_length != 256)
        {
            throw std::invalid_argument("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
        }
    }

    std::vector<uint8_t> utf8_to_bytes(const std::string &utf8_str)
    {
        return std::vector<uint8_t>(utf8_str.begin(), utf8_str.end());
    }

    std::string bytes_to_utf8(const std::vector<uint8_t> &bytes_data)
    {
        std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>);
        std::string result(bytes_data.begin(), bytes_data.end());
        return result;
    }

    std::vector<uint8_t> binary_to_bytes(const std::string &binary_str)
    {
        std::string padded_binary_str = binary_str;
        int padding_length = 8 - (binary_str.size() % 8);
        padded_binary_str += '1' + std::string(padding_length - 1, '0');
        std::vector<uint8_t> bytes((padded_binary_str.size() + 7) / 8);
        for (size_t i = 0; i < padded_binary_str.size(); i += 8)
        {
            bytes[i / 8] = std::bitset<8>(padded_binary_str.substr(i, 8)).to_ulong();
        }
        return bytes;
    }

    std::string bytes_to_binary(const std::vector<uint8_t> &bytes_data)
    {
        std::string binary_str;
        for (uint8_t byte : bytes_data)
        {
            binary_str += std::bitset<8>(byte).to_string();
        }
        size_t last_one_index = binary_str.rfind('1');
        return "0b" + binary_str.substr(0, last_one_index);
    }

    std::vector<uint8_t> pkcs7_padding(const std::vector<uint8_t> &data)
    {
        size_t padding_length = 16 - (data.size() % 16);
        std::vector<uint8_t> padded_data = data;
        padded_data.insert(padded_data.end(), padding_length, padding_length);
        return padded_data;
    }

    std::vector<uint8_t> pkcs7_unpadding(const std::vector<uint8_t> &data)
    {
        size_t padding_length = data.back();
        return std::vector<uint8_t>(data.begin(), data.end() - padding_length);
    }

    std::string to_hex(const std::vector<uint8_t> &data)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (const auto &byte : data)
        {
            oss << std::setw(2) << static_cast<int>(byte);
        }
        return oss.str();
    }

    std::vector<uint8_t> cbc_encrypt(const std::string &plaintext)
    {
        std::vector<uint8_t> padded_data = pkcs7_padding(utf8_to_bytes(plaintext));
        std::vector<uint8_t> encrypted_blocks;
        std::vector<uint8_t> previous_block = iv;

        // std::cout << "The Initial Vector IV: " << to_hex(previous_block) << std::endl;

        for (size_t i = 0; i < padded_data.size(); i += 16)
        {
            std::vector<uint8_t> block(padded_data.begin() + i, padded_data.begin() + i + 16);
            for (size_t j = 0; j < 16; ++j)
            {
                block[j] ^= previous_block[j];
            }
            std::vector<uint8_t> encrypted_block = aes.encrypt(block);
            encrypted_blocks.insert(encrypted_blocks.end(), encrypted_block.begin(), encrypted_block.end());
            previous_block = encrypted_block;
        }

        std::vector<uint8_t> result = iv;
        result.insert(result.end(), encrypted_blocks.begin(), encrypted_blocks.end());
        return result;
    }

    std::string cbc_decrypt(const std::vector<uint8_t> &ciphertext)
    {
        if (ciphertext.size() % 16 != 0)
        {
            throw std::invalid_argument("Ciphertext length must be a multiple of 16 bytes for CBC mode.");
        }

        std::vector<uint8_t> decrypted_blocks;
        std::vector<uint8_t> previous_block(ciphertext.begin(), ciphertext.begin() + 16);
        std::vector<uint8_t> encrypted_data(ciphertext.begin() + 16, ciphertext.end());

        // std::cout << "The Initial Vector IV: " << to_hex(previous_block) << std::endl;

        for (size_t i = 0; i < encrypted_data.size(); i += 16)
        {
            std::vector<uint8_t> block(encrypted_data.begin() + i, encrypted_data.begin() + i + 16);
            std::vector<uint8_t> decrypted_block = aes.decrypt(block);
            for (size_t j = 0; j < 16; ++j)
            {
                decrypted_block[j] ^= previous_block[j];
            }
            decrypted_blocks.insert(decrypted_blocks.end(), decrypted_block.begin(), decrypted_block.end());
            previous_block = block;
        }

        std::vector<uint8_t> unpadded_data = pkcs7_unpadding(decrypted_blocks);
        return bytes_to_utf8(unpadded_data);
    }
};

std::string message_to_bin(const std::string &message)
{
    std::string binary_message;
    for (unsigned char byte : message)
    {
        binary_message += std::bitset<8>(byte).to_string();
    }
    return binary_message;
}

void aes_mode_test()
{
    std::string key;
    std::cout << "Input Secret Key:\n";
    std::getline(std::cin, key);

    std::string iv;
    std::cout << "Input Initial Vector:\n";
    std::getline(std::cin, iv);

    if (iv.length() != 16)
    {
        std::cerr << "Initial Vector IV length must be 16 bytes" << std::endl;
        return;
    }

    std::vector<unsigned char> key_bytes(key.begin(), key.end());
    Modes aes_mode(key_bytes, std::vector<unsigned char>(iv.begin(), iv.end()));
    std::cout << "Do you want to encrypt or decrypt (e/d)? ";
    char choice;
    std::cin >> choice;
    std::cin.ignore();
    if (choice == 'e' || choice == 'E')
    {
        std::string plaintext;
        std::cout << "Input plaintext:\n";
        std::getline(std::cin, plaintext);

        std::vector<unsigned char> cipher = aes_mode.cbc_encrypt(plaintext);
        auto decrypt_function = [&aes_mode](const std::vector<unsigned char> &ciphertext)
        {
            return aes_mode.cbc_decrypt(ciphertext);
        };

        std::cout << "Ciphertext:\n";
        for (unsigned char c : cipher)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        std::cout << std::endl;
    }
    else if (choice == 'd' || choice == 'D')
    {
        std::string ciphertext_hex;
        std::cout << "Input Ciphertext:\n";
        std::getline(std::cin, ciphertext_hex);
        auto decrypt_function = [&aes_mode](const std::vector<unsigned char> &ciphertext)
        {
            return aes_mode.cbc_decrypt(ciphertext);
        };

        std::vector<unsigned char> ciphertext;
        for (size_t i = 0; i < ciphertext_hex.length(); i += 2)
        {
            std::string byteString = ciphertext_hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            ciphertext.push_back(byte);
        }

        std::string recovered_text = decrypt_function(ciphertext);
        std::cout << "Recovered text:\n";
        for (unsigned char c : recovered_text)
        {
            std::cout << c;
        }
        std::cout << std::endl;
    }
    else
    {
        std::cout << "Invalid command." << std::endl;
    }
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    aes_mode_test();
    return 0;
}
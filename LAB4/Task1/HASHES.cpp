#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include <fstream>
using std::ifstream;
using std::istreambuf_iterator;
using std::ofstream;

#include <string>
using std::string;

#include "cryptopp/sha.h"
using CryptoPP::SHA224;
using CryptoPP::SHA256;
using CryptoPP::SHA384;
using CryptoPP::SHA512;

#include "cryptopp/sha3.h"
using CryptoPP::SHA3_224;
using CryptoPP::SHA3_256;
using CryptoPP::SHA3_384;
using CryptoPP::SHA3_512;

#include "cryptopp/shake.h"
using CryptoPP::SHAKE128;
using CryptoPP::SHAKE256;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::HashFilter;
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#ifdef _WIN32
#include <windows.h>
#endif

#include <cstdlib>
#include <locale>
#include <cctype>
#include <numeric>
#include <vector>
#include <chrono>
using namespace std::chrono;

#include <time.h>

void HashFunction(const string &input, const string &hashType, int shakeDigestLength = 0)
{
    string output;
    HexEncoder encoder(new StringSink(output));

    if (hashType == "SHA224")
    {
        SHA224 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA256")
    {
        SHA256 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA384")
    {
        SHA384 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA512")
    {
        SHA512 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA3-224")
    {
        SHA3_224 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA3-256")
    {
        SHA3_256 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA3-384")
    {
        SHA3_384 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA3-512")
    {
        SHA3_512 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHAKE128")
    {
        SHAKE128 hash(shakeDigestLength);
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHAKE256")
    {
        SHAKE256 hash(shakeDigestLength);
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else
    {
        cerr << "Invalid hash type!" << endl;
        return;
    }

    cout << "Digest (" << hashType << "): " << output << endl;
}

void HashFunction1(const string &input, const string &hashType, int shakeDigestLength = 0)
{
    string output;
    HexEncoder encoder(new StringSink(output));

    if (hashType == "SHA224")
    {
        SHA224 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA256")
    {
        SHA256 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA384")
    {
        SHA384 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA512")
    {
        SHA512 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA3-224")
    {
        SHA3_224 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA3-256")
    {
        SHA3_256 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA3-384")
    {
        SHA3_384 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHA3-512")
    {
        SHA3_512 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHAKE128")
    {
        SHAKE128 hash(shakeDigestLength);
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else if (hashType == "SHAKE256")
    {
        SHAKE256 hash(shakeDigestLength);
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    }
    else
    {
        cerr << "Invalid hash type!" << endl;
        return;
    }

    // cout << "Digest (" << hashType << "): " << output << endl;
}

string ReadFromFile(const string &filename)
{
    ifstream file(filename);
    if (!file.is_open())
    {
        cerr << "Failed to open file: " << filename << endl;
        exit(EXIT_FAILURE);
    }
    return string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

float calculateAverage(const std::vector<float> &vec)
{
    if (vec.empty())
    {
        throw std::invalid_argument("The vector is empty.");
    }

    double sum = std::accumulate(vec.begin(), vec.end(), 0.0);
    return sum / vec.size();
}

void Run(const string &input)
{
    std::vector<float> hash;
    string type[10] = {"SHA224", "SHA256", "SHA384", "SHA512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"};
    // cout << "FileName: " << input << endl;
    for (int i = 0; i < 10; i++)
    {
        for (int k = 0; k < 1000; k++)
        {
            auto start = high_resolution_clock::now();
            if (type[i] == "SHA3-512" || type[i] == "SHAKE128")
            {
                HashFunction1(input, type[i], 32);
            }
            else
            {
                HashFunction1(input, type[i]);
            }
            auto end = high_resolution_clock::now(); // End timing
            auto duration = duration_cast<milliseconds>(end - start);
            hash.push_back(duration.count());
        }
        float hashAverage = calculateAverage(hash);
        cout << "Finished Hash Type: " << type[i] << endl;
        cout << "Average Time: " << hashAverage << " ms" << endl;
    }
}

int main()
{
#ifdef __linux__
    std::locale::global(std::locale("C.utf8"));
#endif

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    // Run();
    // return 0;
    int choice;
    string input;
    string filename;
    int shakeDigestLength = 0;

    cout << "Choose input method:\n1. Input from screen\n2. Input from file\nChoice: ";
    cin >> choice;
    cin.ignore();

    if (choice == 1)
    {
        cout << "Enter the plaintext: ";
        getline(cin, input);
    }
    else if (choice == 2)
    {
        cout << "Enter the filename: ";
        cin >> filename;
        input = ReadFromFile(filename);
    }
    else
    {
        cerr << "Invalid choice!" << endl;
        return EXIT_FAILURE;
    }

    cout << "Choose hash function:\n1. SHA224\n2. SHA256\n3. SHA384\n4. SHA512\n5. SHA3-224\n6. SHA3-256\n7. SHA3-384\n8. SHA3-512\n9. SHAKE128\n10. SHAKE256\nChoice: ";
    cin >> choice;

    string hashType;
    switch (choice)
    {
    case 1:
        hashType = "SHA224";
        break;
    case 2:
        hashType = "SHA256";
        break;
    case 3:
        hashType = "SHA384";
        break;
    case 4:
        hashType = "SHA512";
        break;
    case 5:
        hashType = "SHA3-224";
        break;
    case 6:
        hashType = "SHA3-256";
        break;
    case 7:
        hashType = "SHA3-384";
        break;
    case 8:
        hashType = "SHA3-512";
        break;
    case 9:
        hashType = "SHAKE128";
        cout << "Enter digest output length for SHAKE128: ";
        cin >> shakeDigestLength;
        break;
    case 10:
        hashType = "SHAKE256";
        cout << "Enter digest output length for SHAKE256: ";
        cin >> shakeDigestLength;
        break;
    default:
        cerr << "Invalid choice!" << endl;
        return EXIT_FAILURE;
    }

    HashFunction(input, hashType, shakeDigestLength);

    cout << "Do you want to run 1000 times? (y/n): ";
    char choices;
    cin >> choices;
    if (choices == 'y' || choices == 'Y')
    {
        Run(input);
    }
    else if (choices == 'n' || choices == 'N')
    {
        return 0;
    }
    else
    {
        cerr << "Invalid choice!" << endl;
        return EXIT_FAILURE;
    }

    return 0;
}

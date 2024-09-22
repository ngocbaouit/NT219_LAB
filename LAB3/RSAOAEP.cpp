// Linux help: http://www.cryptopp.com/wiki/Linux

// Debug:
// g++ -g -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp && strip --strip-all cryptopp-key-gen.exe

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

// UTF-8 Vietnamese languages
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/modarith.h>
using CryptoPP::ModularArithmetic;

#include <cstdlib>
#include <locale>
#include <cctype>

#ifndef DLL_EXPORT
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif
#endif

// Save (BER-BIN) key to file
void Save(const string &filename, const BufferedTransformation &bt);
void SavePrivateKey(const string &filename, const PrivateKey &key);
void SavePublicKey(const string &filename, const PublicKey &key);

// Save (BER-BASE64) key to file
void SaveBase64(const string &filename, const BufferedTransformation &bt);
void SaveBase64PrivateKey(const string &filename, const PrivateKey &key);
void SaveBase64PublicKey(const string &filename, const PublicKey &key);

// Load (BER-BIN) key to buffer
void Load(const string &filename, BufferedTransformation &bt);
void LoadPrivateKey(const string &filename, PrivateKey &key);
void LoadPublicKey(const string &filename, PublicKey &key);

// Loat (BER-BASE64) key to buffer
void LoadBase64(const string &filename, BufferedTransformation &bt);
void LoadBase64PrivateKey(const string &filename, RSA::PrivateKey &key);
void LoadBase64PublicKey(const string &filename, RSA::PublicKey &key);

// extern "C"
// {
// 	DLL_EXPORT void GenerateAndSaveRSAKeys(int keySize, const char *format, const char *privateKeyFile, const char *publicKeyFile);
// 	DLL_EXPORT void RSAencrypt(const char *format, const char *publicKeyFile, const char *PlaintextFile, const char *CiphertFile);
// 	DLL_EXPORT void RSAdecrypt(const char *format, const char *privateKeyFile, const char *ciphertextFile, const char *PlaintextFile);
// }

void GenerateAndSaveRSAKeys(int keySize, const char *format, const char *privateKeyFile, const char *publicKeyFile)
{
	// convert commandline char to string
	string strFormat(format);
	string strPrivateKey(privateKeyFile);
	string strPublicKey(publicKeyFile);

	AutoSeededRandomPool rnd;
	// Generate Private key
	RSA::PrivateKey rsaPrivate;
	rsaPrivate.GenerateRandomWithKeySize(rnd, keySize);
	// Generate public key
	RSA::PublicKey rsaPublic(rsaPrivate);

	if (strFormat == "DER")
	{
		// Save keys to file (bin)
		SavePrivateKey(strPrivateKey, rsaPrivate);
		SavePublicKey(strPublicKey, rsaPublic);
	}
	else if (strFormat == "Base64")
	{
		// Save keys to file (base64)
		SaveBase64PrivateKey(strPrivateKey, rsaPrivate);
		SaveBase64PublicKey(strPublicKey, rsaPublic);
	}
	else
	{
		cout << "Unsupported format. Please choose 'DER', 'Base64'. " << endl;
		exit(1);
	}

	Integer modul1 = rsaPrivate.GetModulus();	  // modul n (from private)
	Integer prime1 = rsaPrivate.GetPrime1();	  // prime p
	Integer prime2 = rsaPrivate.GetPrime2();	  // prime p
	Integer SK = rsaPrivate.GetPrivateExponent(); // secret exponent d
	Integer PK = rsaPublic.GetPublicExponent();
	Integer modul2 = rsaPublic.GetModulus(); // modul n (from public)
	cout << " Modulo (private) n = " << modul1 << endl;
	cout << " Modulo (public) n = " << modul2 << endl;
	cout << " Prime number (private) p = " << std::hex << prime1 << endl;
	cout << " Prime number (public) q = " << prime2 << std::dec << endl;
	cout << " Secret exponent d =  " << SK << endl;
	cout << " Public exponent e = " << PK << endl; // 17?

	cout << "Successfully generated and saved RSA keys" << endl;
}

// Encryption
string RSAencrypt(const string format, const char *publicKeyFile, const char *PlaintextFile, const char *CipherFile)
{

	// Load key
	RSA::PrivateKey rsaPrivate;
	RSA::PublicKey rsaPublic;

	if (format == "DER")
	{
		LoadPublicKey(publicKeyFile, rsaPublic);
	}
	else if (format == "Base64")
	{
		LoadBase64PublicKey(publicKeyFile, rsaPublic);
	}
	else
	{
		cout << "Unsupported format";
	}

	// Generate and save random number as hex
	RSAES_OAEP_SHA_Encryptor e(rsaPublic);
	string random;
	AutoSeededRandomPool rng(true, 32);
	// RandomNumberSource(rng, 32, true,
	//     new HexEncoder(
	//         new StringSink(random)
	//     ));

	//  StringSource(random, true,
	// new FileSink("rng.txt", true));

	// RandomNumberSource(rng, 32, true,
	//     new StringSink(random));

	string plain, cipher, hex_cipher;
	FileSource(PlaintextFile, true, new StringSink(plain), false);

	// Encrypt and save cipher
	StringSource(plain, true,
				 new PK_EncryptorFilter(rng, e,
										new StringSink(cipher)) // PK_EncryptorFilter
	);															// StringSource

	StringSource(cipher, true,
				 new FileSink(CipherFile, true));

	// Convert cipher to hex
	StringSource(cipher, true,
				 new HexEncoder(
					 new StringSink(hex_cipher)));

	// cout << "Cipher text: " << hex_cipher << endl;
	return hex_cipher;
}

// Decryption
string RSAdecrypt(const string format, const char *secretKeyFile, const char *CipherFile, const char *PlaintextFile)
{

	RSA::PrivateKey rsaPrivate;
	RSA::PublicKey rsaPublic;
	/*LoadPrivateKey(secretKeyFile, rsaPrivate);*/

	if (format == "DER")
		LoadPrivateKey(secretKeyFile, rsaPrivate);
	else if (format == "Base64")
		LoadBase64PrivateKey(secretKeyFile, rsaPrivate);
	else
		cout << "Unsupported format";

	string cipher, plain;
	FileSource(CipherFile, true, new StringSink(cipher), true);

	// Decrypt and save plaintext
	AutoSeededRandomPool rng(true, 32);

	RSAES_OAEP_SHA_Decryptor d(rsaPrivate);
	StringSource(cipher, true,
				 new PK_DecryptorFilter(rng, d,
										new StringSink(plain)) // PK_EncryptorFilter
	);														   // StringSource

	StringSource(plain, true,
				 new FileSink(PlaintextFile, true));

	// cout << "Plaintext: " << plain << endl;
	return plain;
}

int main(int argc, char **argv)
{
#ifdef _WIN32
	// Set console code page to UTF-8 on Windows C.utf8, CP_UTF8
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);
#endif
	if (argc < 2)
	{
		cerr << "Usage: \n"
			 << argv[0] << " gen <keysize> <format> <privateKeyFile> <publicKeyFile>\n"
			 << argv[0] << " enc <format> <publicKeyFile> <plainFile> <cipherFile>\n"
			 << argv[0] << " dec <format> <privateKeyFile> <plainFile> <cipherFile>\n";
		return -1;
	}

	string mode = argv[1];

	if (mode == "gen" && argc == 6)
	{
		int keySize = std::stoi(argv[2]);
		GenerateAndSaveRSAKeys(keySize, argv[3], argv[4], argv[5]);
	}
	else if (mode == "enc" && argc == 6)
	{
		string cipher = RSAencrypt(argv[2], argv[3], argv[4], argv[5]);
		cout << "Cipher text: " << cipher << endl;
		cout << "Do you want to encrypt 10000 times? (y/n) ";
		char c;
		std::cin >> c;
		if (c == 'y')
		{
			auto start = std::chrono::high_resolution_clock::now();
			for (int i = 0; i < 10000; i++)
			{
				string cipher = RSAencrypt(argv[2], argv[3], argv[4], argv[5]);
				// cout << "Round: " << i << endl;
			}
			auto end = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
			double averageTime = static_cast<double>(duration) / 10000.0;
			std::cout << "Average time for over 10000 rounds: " << averageTime << " ms" << std::endl;
		}
		else if (c == 'n')
		{
			cout << "Goodbye!" << endl;
		}
		else
		{
			cout << "Invalid input" << endl;
		}
	}
	else if (mode == "dec")
	{
		const string format = argv[2];
		const char *private_key = argv[3];
		const char *cipher = argv[5];
		const char *plain = argv[4];
		string plaintext = RSAdecrypt(format, private_key, cipher, plain);
		cout << "Plaintext: " << plaintext << endl;
		cout << "Do you want to decrypt 10000 times? (y/n) ";
		char c;
		std::cin >> c;
		if (c == 'y')
		{
			auto start = std::chrono::high_resolution_clock::now();
			for (int i = 0; i < 10000; i++)
			{
				string palin = RSAdecrypt(format, private_key, cipher, plain);
				// cout << "Round: " << i << endl;
			}
			auto end = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
			double averageTime = static_cast<double>(duration) / 10000.0;
			std::cout << "Average time for over 10000 rounds: " << averageTime << " ms" << std::endl;
		}
		else if (c == 'n')
		{
			cout << "Goodbye!" << endl;
		}
		else
		{
			cout << "Invalid input" << endl;
		}
	}
	else
	{
		cerr << "Invalid arguments. Please check the usage instructions.\n";
		return -1;
	}

	return 0;
}

// Def functions
/* ############################### */
void SavePrivateKey(const string &filename, const PrivateKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string &filename, const PublicKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string &filename, const BufferedTransformation &bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveBase64PrivateKey(const string &filename, const PrivateKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string &filename, const PublicKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64(const string &filename, const BufferedTransformation &bt)
{
	// http://www.cryptopp.com/docs/ref/class_base64_encoder.html
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadBase64PrivateKey(const string &filename, RSA::PrivateKey &key)
{
	// Create a FileSource that automatically decodes Base64 data from the file
	CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::Base64Decoder);

	// Load the decoded data into a ByteQueue
	CryptoPP::ByteQueue queue;
	file.TransferTo(queue);
	queue.MessageEnd();

	// Load the private key from the ByteQueue
	key.Load(queue);

	// Optionally, check the validity of the loaded key
	CryptoPP::AutoSeededRandomPool prng;
	if (!key.Validate(prng, 3))
	{
		throw std::runtime_error("Loaded private key is invalid.");
	}
}

void LoadBase64PublicKey(const string &filename, RSA::PublicKey &key)
{
	// Create a FileSource that automatically decodes Base64 data from the file
	CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::Base64Decoder);

	// Load the decoded data into a ByteQueue
	CryptoPP::ByteQueue queue;
	file.TransferTo(queue);
	queue.MessageEnd();

	// Load the public key from the ByteQueue
	key.Load(queue);
	// Optionally, check the validity of the loaded key
	AutoSeededRandomPool prng;
	if (!key.Validate(prng, 3))
	{
		throw std::runtime_error("Loaded public key is invalid.");
	}
}

void LoadBase64(const string &filename, BufferedTransformation &bt)
{
	throw runtime_error("Not implemented");
}

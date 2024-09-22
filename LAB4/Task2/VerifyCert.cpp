
#include "cryptopp/cryptlib.h"
#include "cryptopp/x509cert.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/filters.h"
#include "cryptopp/pem.h"
#include "cryptopp/hex.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include <iostream>
#include <iomanip>
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>
using namespace CryptoPP;
using namespace std;
void VerifySignature(const X509Certificate& cert) {
    const SecByteBlock& sig = cert.GetCertificateSignature();
    const SecByteBlock& tbs = cert.GetToBeSigned();

    const X509PublicKey& publicKey = cert.GetSubjectPublicKey();
    RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey);
    bool result = verifier.VerifyMessage(tbs, tbs.size(), sig, sig.size());

    if (result)
        std::cout << "\nVerified certificate" << std::endl;
    else
    {
        std::cout << "\nFailed to verify certificate" << std::endl;
        exit(true);
    }
}

void PrintCertificateDetails(const X509Certificate& cert) {
    const SecByteBlock& signature = cert.GetCertificateSignature();
    const SecByteBlock& toBeSigned = cert.GetToBeSigned();
    cout << "\nVersion: " << cert.GetVersion() << endl;
    cout << "\nSerial Number: " << cert.GetSerialNumber() << endl;
    cout << "\nSubject: " << cert.GetSubjectDistinguishedName() << endl;
    cout << "\nIssuer: " << cert.GetIssuerDistinguishedName() << endl;
    cout << "\nValid From: " << cert.GetNotBefore() << endl;
    cout << "\nValid To: " << cert.GetNotAfter() << endl;
    cout << "\nSign Algorithm: " << cert.GetCertificateSignatureAlgorithm() << endl;
    cout << "\nSubject Public Key Algorithm: " << cert.GetSubjectPublicKeyAlgorithm() << endl;
    cout << "\nSignature: ";
    StringSource ss1(signature, signature.size(), true, new HexEncoder(new FileSink(cout)));
    cout << endl;
    cout << "\nTo Be Signed: ";
    StringSource ss2(toBeSigned, toBeSigned.size(), true, new HexEncoder(new FileSink(cout)));
    VerifySignature(cert);
}

void LoadFile(const string& filePath) {
    X509Certificate cert;
    string contents;
    FileSource file(filePath.c_str(), true, new StringSink(contents));
    StringSource ss(contents, true);
    PEM_Load(ss,cert);
    PrintCertificateDetails(cert);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <path_to_certificate>" << endl;
        return 1;
    }
    LoadFile(argv[1]);
    return 0;
}

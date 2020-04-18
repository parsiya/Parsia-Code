// DecryptLog.cpp : Decrypts encrypted log files.
// Lots of useless utility methods to warm up. I had not written C++ in forever.

#include <iostream>
#include <random>
#include <string>
#include <fstream>
#include <stdio.h>
#include <cstddef>

// To get byte in Visual C++.
// 1. Right-click on the solution.
// 2. Properties > C/C++ > Language.
// 3. Change "C++ Language Standard" to "ISO C++17 Standard (/std:c++17)"
// 4. Add <cstddef>.
// 5. Now you can use std::byte.

using namespace std;

// charToByteVector converts vector<char> to vector<byte>.
// Modified from: https://stackoverflow.com/a/52629891.
vector<byte> charToByteVector(const vector<char> chars) {
    vector<byte> bytes;
    for (char c : chars)
        bytes.push_back(static_cast<byte>(c));

    return bytes;
}

// byteToCharVector converts vector<byte> to vector<char>.
vector<char> byteToCharVector(const vector<byte> bytes) {
    vector<char> chars;
    for (byte b : bytes)
        chars.push_back(static_cast<char>(b));

    return chars;
}

// stringToCharVector converts a string to vector<char>.
vector<char> stringToCharVector(const string s) {
    vector<char> chars(s.begin(), s.end());
    return chars;
}

// stringToByteVector converts a string to vector<byte>.
vector<byte> stringToByteVector(const string s) {
    return charToByteVector(stringToCharVector(s));
}

// byteVectorTostring converts a vector<byte> to string.
string byteVectorTostring(const vector<byte> bytes) {
    vector<char> chars = byteToCharVector(bytes);
    return string(chars.data(), chars.size());
}

// slice returns a slice of vector v from indices m to n.
// Copied from: https://www.techiedelight.com/get-slice-sub-vector-from-vector-cpp/.
template<typename T>
std::vector<T> slice(std::vector<T>& v, int m, int n)
{
    std::vector<T> vec;
    std::copy(v.begin() + m, v.begin() + n + 1, std::back_inserter(vec));
    return vec;
}

// readFileString reads a file and returns it a string
// Modified from: https://stackoverflow.com/a/525103.
string readFileString(const string& filename)
{
    ifstream inFile(filename.c_str(), ios::in | ios::binary | ios::ate);

    ifstream::pos_type fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);

    vector<char> fileBytes(fileSize);
    inFile.read(fileBytes.data(), fileSize);
    inFile.close();

    return string(fileBytes.data(), fileSize);
}

// readFileChar reads a file and returns a vector<char>.
// Note the vector is not NULL-terminated.
// Modified from https://stackoverflow.com/a/50317432.
vector<char> readFileChar(const string& filename) {
    ifstream inFile(filename.c_str(), ios::in | ios::binary | ios::ate);

    std::vector<char> fileBytes(
        (istreambuf_iterator<char>(inFile)),
        (istreambuf_iterator<char>()));

    inFile.close();
    return fileBytes;
}

// readFileByte reads a file and returns a vector<byte>.
vector<byte> readFileByte(const string& filename) {
    ifstream inFile(filename.c_str(), ios::in | ios::binary | ios::ate);

    ifstream::pos_type fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);

    vector<char> fileBytes(fileSize);
    inFile.read(fileBytes.data(), fileSize);
    inFile.close();

    return charToByteVector(fileBytes);
}

// writeFileString writes the string to file. Overwrites the existing file if it
// exists.
void writeFileString(const string data, const string filename) {
    ofstream outFile(filename.c_str(), ios::binary);
    outFile << data;
    outFile.close();
}

// writeFileByte writes a vector<byte> to file. Overwrites the existing file if it
// exists.
void writeFileByte(const vector<byte> data, const string filename) {
    ofstream outFile(filename.c_str(), ios::binary);
    outFile << byteVectorTostring(data);
    outFile.close();
}

// getKeys seeds the 32-bit mt19937 with 0x25082011 and returns a vector<byte>
// with num keys. Where key is the largest byte of the uint32 number generated
// by the mt19937 engine.
vector<byte> getKeys(const int num) {

    vector<byte> keys;
    // Custom seed.
    mt19937 generator(0x25082011);
    for (size_t i = 0; i < num; i++)
    {
        unsigned int num = generator();
        // Get the byte in AL.
        num = (num & 0xFF000000) >> 24;
        // Store it in the vector.
        keys.push_back(byte(num));
    }

    return keys;
}

const string s_LOGZ = "LOGZ";

// checkFileHeader compares the first 4 bytes of input with LOGZ.
// Returns true if they match.
bool checkHeader(vector<byte> input) {

    // Convert s_LOGZ to vector<byte>
    vector<byte> vectorLOGZ = stringToByteVector(s_LOGZ);

    // 3.1.2 Get the first 4 bytes of input file (vector<byte> enc).
    vector<byte> fileHeader = slice(input, 0, 3);

    return (vectorLOGZ == fileHeader);
}

const vector<byte> version{ byte{0x20}, byte{0x10}, byte{0xAB}, byte{0x01} };

// checkVersion compares the second 4 bytes of input with version.
bool checkVersion(vector<byte> input) {
    vector<byte> fileVersion = slice(input, 4, 7);
    return (fileVersion == version);
}

int main(int argc, char* argv[], char* envp[])
{
    // 1. Read command line parameters.
    // 1.1 First should be the input file and second the output file.

    string usage("Usage: DecryptLog EncryptedLogFile DecryptedFilePath");

    // 1.2 If we do not have 3 arguments (including the executable name)
    if (argc != 3) {
        cout << "Please provide two arguments." << endl;
        cout << usage;
        return 1;
    }

    // 1.3 Open the first argument.
    string inPath = argv[1];
    string outPath = argv[2];

    // cout << "Got argv[1]: " << inPath << endl;
    // cout << "Got argv[2]: " << outPath << endl;

    vector<byte> inputBytes;

    // 2. Read the data from inputFile.
    cout << "Reading from " << inPath << endl;
    try
    {
        inputBytes = readFileByte(inPath);
    }
    catch (const std::exception& e)
    {
        cerr << "Exception opening input file at " << inPath << " - Error: " << e.what() << endl;
        return 1;
    }

    // 3. Check the header
    // 3.1 Check the first 4 bytes. They should be LOGZ.
    if (checkHeader(inputBytes)) {
        cout << "File header is correct." << endl;
    }
    else {
        cout << "File header is incorrect. Wanted: " << s_LOGZ << " , got: " << slice(inputBytes,0,3).data() << endl;
        return 1;
    }
 
    // 3.2 Check the version. Next 4 bytes should be 0x20, 0x10, 0xAB, 0x01.
    if (checkVersion(inputBytes)) {
        cout << "File version is correct." << endl;
    }
    else {
        cout << "File version is incorrect. Wanted: " << version.data() << " , got: " << slice(inputBytes, 4, 7).data() << endl;
        return 1;
    }

    // 4. Decrypt.
    cout << "Decrypting." << endl;
    // 4.1 Create the plaintext vector<byte>.
    // First 8 bytes are already accounted for.
    vector<byte> ciphertext = slice(inputBytes, 8, inputBytes.size()-1);
    vector<byte> plaintext;

    // 4.2 Get the key stream.
    vector<byte> key = getKeys(ciphertext.size());

    // 4.3 XOR key and ciphertext
    for (size_t i = 0; i < ciphertext.size(); i++)
    {
        plaintext.push_back(ciphertext[i] ^ key[i]);
    }

    cout << "Ciphertext size: " << ciphertext.size() << endl;
    cout << "Plaintext size : " << plaintext.size() << endl;

    // 5. Write it to the outfile.
    cout << "Writing the output to " << outPath << endl;
    try
    {
        writeFileByte(plaintext, outPath);
    }
    catch (const std::exception& e)
    {
        cerr << "Exception writing to file at " << inPath << " - Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}


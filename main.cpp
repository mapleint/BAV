#include <iostream>
#include <vector>


const unsigned int s[] = { 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 };

const unsigned int K[] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

unsigned int og[] = { 0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476
};

#define inrange(lower, x, upper) (lower <= x && x <= upper)
int rotateLeft(unsigned int x, unsigned int n) {
    return ((x << n) | (x >> (32 - n)));
}

/*md5 checksum algorithm*/
std::string md5(const char* data, size_t len) {

    std::vector<unsigned char> message = {};

    for (int i = 0; i < len; i++)
        message.push_back(data[i]);

    message.push_back(0x80);

    while (message.size() % 64 != 56)
        message.push_back(0x00);

    /*goofy endianness, missing the * 8 cost me a while to fix*/
    message.push_back((len * 8 & 0x000000ff) >> 0);
    message.push_back((len * 8 & 0x0000ff00) >> 8);
    message.push_back((len * 8 & 0x00ff0000) >> 16);
    message.push_back((len * 8 & 0xff000000) >> 24);

    for (int i = 0; i < 4; i++) {
        message.push_back(0x00);
    }

    for (size_t i = 0; i < message.size() / 64; i++) {
        unsigned int* M = (unsigned int*)(message.data() + i * 4);

        unsigned int a = og[0], b = og[1], c = og[2], d = og[3];

        for (int j = 0; j < 64; j++) {
            unsigned int F = 0, g = 0;
            if (inrange(0, j, 15)) {
                F = (b & c) | ((~b) & d);
                g = j;
            }
            else if (inrange(16, j, 31)) {
                F = (d & b) | ((~d) & c);
                g = (5 * j + 1) % 16;
            }
            else if (inrange(32, j, 47)) {
                F = b ^ c ^ d;
                g = (3 * j + 5) % 16;
            }
            else if (inrange(48, j, 63)) {
                F = c ^ (b | (~d));
                g = (7 * j) % 16;
            }
            F += a + K[j] + M[g];
            a = d;
            d = c;
            c = b;
            b += rotateLeft(F, s[j]);
        }
        og[0] += a;
        og[1] += b;
        og[2] += c;
        og[3] += d;
    }

    char* digest = (char*)og;

    std::string out;
    for (int i = 0; i < 16; i++) {
        char buf[3] = { 0 };
        sprintf_s(buf, 3, "%02hhx", digest[i]);
        out += buf;
    }
    return out;
    return 0;
}

constexpr size_t dblen = 1;
std::string db[dblen] = { "098f6bcd4621d373cade4e832627b4f6" };

int match(std::string hash)
{
    for (int i = 0; i < dblen; i++) {
        if (!db[i].compare(hash))
            return 1;
    }
    return 0;
}
#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>
namespace fs = std::filesystem;

int main()
{
    for (const auto& entry : fs::directory_iterator("C:\\Users\\alber\\Documents")) {
        std::ifstream filedata(entry.path().c_str(), std::ios::binary);
        char* pBuf = (char*)malloc(entry.file_size());
        filedata.read(pBuf, entry.file_size());
        auto hash = md5(pBuf, entry.file_size());
        bool found = match(hash);
        std::cout << entry.path() << " : " << hash << std::endl;
        if (found) {
            std::cout << "IMPORTANT! File [" << entry.path() << "] found malicious!" << std::endl;
        }
        free(pBuf);

    }

}

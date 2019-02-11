
#include "dnsserver.h"


#include <unistd.h>
#include <cctype>
#include <cstdio>

using namespace utils;
using std::vector;

namespace
{
    int check_all_digit(const string &part)
    {
        return std::stoi(part);
    }

}  // namespace


namespace utils
{
    void split(vector<string> &vec, const CH *s, const CH c)
    {
        const auto bak = strdup(s);
        auto begin     = bak;
        auto ptr       = bak;
        do {
            for (; *ptr;) {
                if (*ptr == c) {
                    *ptr = 0;
                    vec.emplace_back(begin);
                    begin = ptr = ptr + 1;
                    continue;
                }
                ptr++;
            }
            if (*ptr == 0) {
                if (begin != ptr) {
                    vec.emplace_back(begin);
                }
                break;
            }
        } while (true);
        strfree(bak);
    }

    bool check_ip_address(const CH *ip, uint32_t &address)
    {
        vector<string> ip_part;
        split(ip_part, ip, '.');
        if (ip_part.size() == 4) {
            auto all_digit = true;
            for (auto &part : ip_part) {
                const auto ret = check_all_digit(part);
                all_digit      = all_digit && (ret >= 0 && ret <= 250);
                address        = (address << 8) | static_cast<uint8_t>(ret);
            }
            return all_digit;
        }
        return false;
    }

    // print_able

    print_able::~print_able() {}


    //lostream

}  // namespace utils

void ip_address::to_string(string &buffer) const
{
    if (buffer.capacity() < 20) {
        buffer.reserve(20);
    }
    char buf[8];
    for (int i = 0; i < 4; i++) {
        uint8_t part = (address_ >> ((3 - i) * 8)) & 0xff;
        sprintf(buf, "%d.", part);
        buffer.append(buf);
    }
    buffer.erase(buffer.length() - 1);
}

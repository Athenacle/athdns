
#include "dnsserver.h"
#include "logging.h"

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
        auto begin = bak;
        auto ptr = bak;
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
                all_digit = all_digit && (ret >= 0 && ret <= 250);
                address = (address << 8) | static_cast<uint8_t>(ret);
            }
            return all_digit;
        }
        return false;
    }

}  // namespace utils

namespace logging
{
    void set_default_level(log_level ll)
    {
        auto level = spdlog::level::debug;
        switch (ll) {
            case utils::LL_TRACE:
                level = spdlog::level::debug;
                break;
            case utils::LL_ERROR:
                level = spdlog::level::err;
                break;
            case utils::LL_WARNING:
                level = spdlog::level::warn;
                break;
            case utils::LL_INFO:
                level = spdlog::level::info;
                break;
            case utils::LL_OFF:
                level = spdlog::level::off;
                break;

            default:
                level = spdlog::level::info;
                break;
        }
        spdlog::set_level(level);
    }

    void init_logging() {}


}  // namespace logging

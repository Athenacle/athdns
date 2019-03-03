
#ifndef FORMAT_H
#define FORMAT_H

#include "record.h"

#include <fmt/format.h>

namespace fmt
{
    template <>
    struct formatter<record_node> {
        template <typename PC>
        constexpr auto parse(PC &ctx)
        {
            return ctx.begin();
        }

        template <typename FC>
        auto format(const record_node &p, FC &ctx)
        {
            string str;
            p.to_string(str);
            return format_to(ctx.begin(), "{0}->{0}", p.get_name(), str);
        }
    };
}  // namespace fmt

#endif

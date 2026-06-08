#ifndef SENTRY_OPTIONAL_COMPAT_H
#define SENTRY_OPTIONAL_COMPAT_H

#if defined(__has_include) && __has_include(<optional>)
#  include <optional>
#else
#  include <experimental/optional>
namespace std {
    using experimental::optional;
    using experimental::nullopt;
    using experimental::make_optional;
    using experimental::bad_optional_access;
}
#endif

#endif // SENTRY_OPTIONAL_COMPAT_H

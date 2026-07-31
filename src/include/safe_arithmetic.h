// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <concepts>
#include <optional>

namespace shinku {

template<std::integral T>
[[nodiscard]] std::optional<T> safe_add(T lhs, T rhs) noexcept {
    T result;
    if (__builtin_add_overflow(lhs, rhs, &result)) [[unlikely]]
        return std::nullopt;
    return result;
}

template<std::integral T>
[[nodiscard]] std::optional<T> safe_mul(T lhs, T rhs) noexcept {
    T result;
    if (__builtin_mul_overflow(lhs, rhs, &result)) [[unlikely]]
        return std::nullopt;
    return result;
}

} // namespace shinku

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace shinku::cache::test {

using Message = std::vector<std::byte>;

inline void append_u16(Message& message, uint16_t value) {
    message.push_back(static_cast<std::byte>(value >> 8U));
    message.push_back(static_cast<std::byte>(value & 0xffU));
}

inline void append_u32(Message& message, uint32_t value) {
    message.push_back(static_cast<std::byte>(value >> 24U));
    message.push_back(static_cast<std::byte>((value >> 16U) & 0xffU));
    message.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
    message.push_back(static_cast<std::byte>(value & 0xffU));
}

inline Message header(uint16_t flags, uint16_t questions, uint16_t answers, uint16_t authorities, uint16_t additional) {
    Message message;
    message.reserve(512);
    append_u16(message, 0x1234);
    append_u16(message, flags);
    append_u16(message, questions);
    append_u16(message, answers);
    append_u16(message, authorities);
    append_u16(message, additional);
    return message;
}

inline Message wire_name(std::string_view name) {
    Message wire;
    if (name.empty() || name == ".") {
        wire.push_back(std::byte { 0 });
        return wire;
    }

    size_t label_start = 0;
    while (label_start < name.size()) {
        size_t label_end = name.find('.', label_start);
        if (label_end == std::string_view::npos)
            label_end = name.size();
        const auto label_size = label_end - label_start;
        wire.push_back(static_cast<std::byte>(label_size));
        for (char octet: name.substr(label_start, label_size))
            wire.push_back(static_cast<std::byte>(octet));
        label_start = label_end + 1;
    }
    wire.push_back(std::byte { 0 });
    return wire;
}

inline void append_bytes(Message& message, std::span<const std::byte> bytes) {
    message.insert(message.end(), bytes.begin(), bytes.end());
}

inline void
append_question(Message& message, std::span<const std::byte> encoded_name, uint16_t type, uint16_t rr_class) {
    append_bytes(message, encoded_name);
    append_u16(message, type);
    append_u16(message, rr_class);
}

inline void append_record(
    Message& message,
    std::span<const std::byte> owner,
    uint16_t type,
    uint16_t rr_class,
    uint32_t ttl,
    std::span<const std::byte> rdata
) {
    append_bytes(message, owner);
    append_u16(message, type);
    append_u16(message, rr_class);
    append_u32(message, ttl);
    append_u16(message, static_cast<uint16_t>(rdata.size()));
    append_bytes(message, rdata);
}

inline Message recursive_response(uint16_t answers, uint16_t authorities = 0, uint16_t additional = 0) {
    constexpr uint16_t kQrRdRa = 0x8180;
    auto message = header(kQrRdRa, 1, answers, authorities, additional);
    const auto question_name = wire_name("www.example");
    append_question(message, question_name, 1, 1);
    return message;
}

inline Message pointer_owner(uint8_t low_byte = 0x0c) {
    return { std::byte { 0xc0 }, static_cast<std::byte>(low_byte) };
}

inline Message ipv4_rdata(uint8_t last_octet = 1) {
    return { std::byte { 192 }, std::byte { 0 }, std::byte { 2 }, static_cast<std::byte>(last_octet) };
}

} // namespace shinku::cache::test

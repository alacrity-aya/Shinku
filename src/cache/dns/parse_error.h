// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>

namespace shinku::cache::dns {

enum class ParseError : uint8_t {
    MessageTooLarge,
    HeaderTruncated,
    NameTruncated,
    InvalidLabelType,
    NameTooLong,
    QuestionFieldsTruncated,
    ResourceRecordHeaderTruncated,
    ResourceDataTruncated,
};

} // namespace shinku::cache::dns

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>

namespace shinku::cache::dns {

/// Failure codes returned by @ref parse_response when a DNS message is malformed.
enum class ParseError : uint8_t {
    MessageTooLarge, ///< The message exceeded @ref kMaxDnsMessageBytes.
    HeaderTruncated, ///< Fewer than 12 bytes were present for the header.
    NameTruncated, ///< A name ran past the end of the message.
    InvalidLabelType, ///< A label used an unsupported label-type byte.
    NameTooLong, ///< A name exceeded @ref CanonicalDnsName::kMaxWireSize.
    QuestionFieldsTruncated, ///< The question's type/class ran past the end.
    ResourceRecordHeaderTruncated, ///< A resource record header ran past the end.
    ResourceDataTruncated, ///< A resource record's RDATA ran past the end.
};

} // namespace shinku::cache::dns

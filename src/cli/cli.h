// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <variant>

namespace shinku::cli {

enum class CliErrorCode : uint8_t {
    MissingSubcommand,
    UnexpectedArgument,
};

struct CliError {
    CliErrorCode code;
    std::string message;
};

struct CliCommand {
    std::filesystem::path config_path;
};

enum class CliAction : uint8_t {
    ShowHelp,
    ShowVersion,
};

using CliResult = std::variant<CliCommand, CliAction>;

std::expected<CliResult, CliError> parse_cli(int argc, char** argv);

std::string_view usage_text();

} // namespace shinku::cli

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace shinku::cli {

enum class CliErrorCode : uint8_t {
    MissingSubcommand,
    UnsupportedSubcommand,
    MissingConfigPath,
    UnsupportedOption,
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
    Run,
    ShowHelp,
    ShowVersion,
};

struct CliResult {
    CliAction action;
    std::optional<CliCommand> command;
};

std::expected<CliResult, CliError> parse_cli(int argc, char** argv);

std::string_view usage_text();

} // namespace shinku::cli

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <expected>
#include <filesystem>
#include <optional>
#include <string>

namespace shinku::cli {

enum class CliErrorCode {
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

enum class CliAction {
    Run,
    ShowHelp,
    ShowVersion,
};

struct CliResult {
    CliAction action;
    std::optional<CliCommand> command;
};

std::expected<CliResult, CliError> parse_cli(int argc, char** argv);

const char* usage_text();

} // namespace shinku::cli

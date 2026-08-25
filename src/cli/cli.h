// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace shinku::cli {

/// Failure codes returned by @ref parse_cli.
enum class CliErrorCode : uint8_t {
    MissingSubcommand, ///< No subcommand was supplied on the command line.
    UnexpectedArgument, ///< An argument was supplied that the CLI does not accept.
};

/// Error returned by @ref parse_cli, carrying a code and message.
struct CliError {
    CliErrorCode code; ///< The failure category.
    std::string message; ///< Human-readable description of the failure.
};

/// A parsed `shinku run` command, ready to drive the application.
struct CliCommand {
    std::filesystem::path config_path; ///< Path to the TOML configuration file.
    std::vector<std::string> dpdk_arguments; ///< EAL arguments forwarded after `--` for the DPDK backend.
};

/// Immediate actions the CLI may resolve to instead of running the application.
enum class CliAction : uint8_t {
    ShowHelp, ///< Print the usage text and exit.
    ShowVersion, ///< Print the version string and exit.
};

/// The outcome of parsing the command line: either a runnable command or an immediate action.
using CliResult = std::variant<CliCommand, CliAction>;

/**
 * @brief Parse the process command line.
 *
 * Accepts `shinku run [--config path] [-- arg...]`, `shinku --help`, and
 * `shinku --version`. Arguments after `--` are collected verbatim as DPDK
 * EAL arguments and are not interpreted by the CLI.
 *
 * @param argc Argument count from @c main.
 * @param argv Argument vector from @c main.
 * @return A command or immediate action, or a @ref CliError on failure.
 */
std::expected<CliResult, CliError> parse_cli(int argc, char** argv);

/**
 * @brief Return the CLI usage text.
 * @return A stable string view of the usage message.
 */
std::string_view usage_text();

} // namespace shinku::cli

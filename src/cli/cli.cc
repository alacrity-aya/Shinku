// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cli/cli.h"

#include <string_view>

namespace shinku::cli {
namespace {

constexpr std::string_view kRun = "run";
constexpr std::string_view kConfig = "--config";
constexpr std::string_view kHelp = "--help";
constexpr std::string_view kVersion = "--version";

std::unexpected<CliError> cli_error(CliErrorCode code, std::string message) {
    return std::unexpected(CliError{
        .code = code,
        .message = std::move(message),
    });
}

bool looks_like_option(std::string_view arg) {
    return arg.starts_with("-");
}

} // namespace

const char* usage_text() {
    return "usage: shinku run [--config path]\n";
}

std::expected<CliResult, CliError> parse_cli(int argc, char** argv) {
    if (argc <= 1)
        return cli_error(CliErrorCode::MissingSubcommand, "expected subcommand: run");

    const std::string_view first(argv[1] ? argv[1] : "");

    if (first == kHelp) {
        if (argc == 2)
            return CliResult{ .action = CliAction::ShowHelp, .command = std::nullopt };
        return cli_error(CliErrorCode::UnexpectedArgument, "unexpected argument after --help");
    }

    if (first == kVersion) {
        if (argc == 2)
            return CliResult{ .action = CliAction::ShowVersion, .command = std::nullopt };
        return cli_error(CliErrorCode::UnexpectedArgument, "unexpected argument after --version");
    }

    if (looks_like_option(first))
        return cli_error(CliErrorCode::UnsupportedOption, "unsupported option: " + std::string(first));

    if (first != kRun)
        return cli_error(CliErrorCode::UnsupportedSubcommand, "unsupported subcommand: " + std::string(first));

    if (argc == 3) {
        const std::string_view arg(argv[2] ? argv[2] : "");
        if (arg == kHelp)
            return CliResult{ .action = CliAction::ShowHelp, .command = std::nullopt };
        if (arg == kConfig)
            return cli_error(CliErrorCode::MissingConfigPath, "missing path after --config");
        if (looks_like_option(arg))
            return cli_error(CliErrorCode::UnsupportedOption, "unsupported option: " + std::string(arg));
        return cli_error(CliErrorCode::UnexpectedArgument, "unexpected argument: " + std::string(arg));
    }

    std::filesystem::path config_path("./shinku.toml");
    bool has_config = false;

    for (int i = 2; i < argc; i++) {
        const std::string_view arg(argv[i] ? argv[i] : "");

        if (arg == kConfig) {
            if (has_config)
                return cli_error(CliErrorCode::UnexpectedArgument, "duplicate --config");
            if (i + 1 >= argc)
                return cli_error(CliErrorCode::MissingConfigPath, "missing path after --config");

            const std::string_view path_arg(argv[i + 1] ? argv[i + 1] : "");
            if (path_arg.empty())
                return cli_error(CliErrorCode::MissingConfigPath, "missing path after --config");
            if (looks_like_option(path_arg))
                return cli_error(CliErrorCode::MissingConfigPath, "missing path after --config");

            config_path = std::filesystem::path(path_arg);
            has_config = true;
            i++;
            continue;
        }

        if (looks_like_option(arg))
            return cli_error(CliErrorCode::UnsupportedOption, "unsupported option: " + std::string(arg));

        return cli_error(CliErrorCode::UnexpectedArgument, "unexpected argument: " + std::string(arg));
    }

    return CliResult{
        .action = CliAction::Run,
        .command = CliCommand{ .config_path = config_path },
    };
}

} // namespace shinku::cli

// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cli/cli.h"

#include <argparse/argparse.hpp>

#include <expected>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace shinku::cli {
namespace {

constexpr std::string_view kRun = "run";
constexpr std::string_view kConfig = "--config";
constexpr std::string_view kHelp = "--help";
constexpr std::string_view kVersion = "--version";
constexpr std::string_view kDefaultConfigPath = "./shinku.toml";

std::unexpected<CliError> cli_error(CliErrorCode code, std::string message) {
    return std::unexpected(CliError {
        .code = code,
        .message = std::move(message),
    });
}

} // namespace

std::string_view usage_text() {
    return "usage: shinku run [--config path]\n";
}

std::expected<CliResult, CliError> parse_cli(int argc, char** argv) {
    argparse::ArgumentParser program("shinku", "", argparse::default_arguments::none);
    argparse::ArgumentParser run_command(std::string(kRun), "", argparse::default_arguments::none);

    program.add_argument(std::string(kHelp)).default_value(false).implicit_value(true);
    program.add_argument(std::string(kVersion)).default_value(false).implicit_value(true);

    run_command.add_argument(std::string(kHelp)).default_value(false).implicit_value(true);
    run_command.add_argument(std::string(kConfig)).metavar("path").nargs(1);

    program.add_subparser(run_command);

    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& error) {
        return cli_error(CliErrorCode::UnexpectedArgument, error.what());
    }

    if (program.get<bool>(std::string(kHelp)))
        return CliResult { .action = CliAction::ShowHelp, .command = std::nullopt };

    if (program.get<bool>(std::string(kVersion)))
        return CliResult { .action = CliAction::ShowVersion, .command = std::nullopt };

    if (!program.is_subcommand_used(run_command))
        return cli_error(CliErrorCode::MissingSubcommand, "expected subcommand: run");

    if (run_command.get<bool>(std::string(kHelp)))
        return CliResult { .action = CliAction::ShowHelp, .command = std::nullopt };

    std::filesystem::path config_path(kDefaultConfigPath);
    auto explicit_config = run_command.present<std::vector<std::string>>(std::string(kConfig));
    if (explicit_config.has_value())
        config_path = explicit_config.value().front();

    return CliResult {
        .action = CliAction::Run,
        .command = CliCommand { .config_path = config_path },
    };
}

} // namespace shinku::cli

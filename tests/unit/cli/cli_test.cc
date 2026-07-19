// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cli/cli.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

int tests_run = 0;
int tests_failed = 0;

void expect(bool condition, const std::string& message) {
    tests_run++;
    if (!condition) {
        tests_failed++;
        std::cerr << "FAIL: " << message << '\n';
    }
}

std::expected<shinku::cli::CliResult, shinku::cli::CliError> parse(std::initializer_list<const char*> args) {
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (const char* arg : args)
        argv.push_back(const_cast<char*>(arg));
    return shinku::cli::parse_cli(static_cast<int>(argv.size()), argv.data());
}

void accepts_default_config_path() {
    auto result = parse({ "shinku", "run" });
    expect(result.has_value(), "shinku run should parse");
    expect(result->action == shinku::cli::CliAction::Run, "shinku run should produce Run action");
    expect(result->command.has_value(), "Run action should carry a command");
    expect(result->command->config_path == std::filesystem::path("./shinku.toml"), "default config path should be exact");
}

void accepts_explicit_config_path() {
    auto result = parse({ "shinku", "run", "--config", "custom.toml" });
    expect(result.has_value(), "shinku run --config custom.toml should parse");
    expect(result->command->config_path == std::filesystem::path("custom.toml"), "explicit config path should be preserved");
}

void accepts_help_and_version_actions() {
    auto root_help = parse({ "shinku", "--help" });
    auto run_help = parse({ "shinku", "run", "--help" });
    auto version = parse({ "shinku", "--version" });

    expect(root_help.has_value(), "shinku --help should parse");
    expect(root_help->action == shinku::cli::CliAction::ShowHelp, "root help should be ShowHelp");
    expect(!root_help->command.has_value(), "help should not carry a run command");

    expect(run_help.has_value(), "shinku run --help should parse");
    expect(run_help->action == shinku::cli::CliAction::ShowHelp, "run help should be ShowHelp");

    expect(version.has_value(), "shinku --version should parse");
    expect(version->action == shinku::cli::CliAction::ShowVersion, "version should be ShowVersion");
}

void rejects_unsupported_forms() {
    auto missing = parse({ "shinku" });
    auto root_config = parse({ "shinku", "--config", "custom.toml" });
    auto short_config = parse({ "shinku", "run", "-c", "custom.toml" });
    auto backend_flag = parse({ "shinku", "run", "--backend", "ebpf" });
    auto short_help = parse({ "shinku", "-h" });
    auto run_version = parse({ "shinku", "run", "--version" });
    auto duplicate_config = parse({ "shinku", "run", "--config", "a.toml", "--config", "b.toml" });
    auto missing_config_path = parse({ "shinku", "run", "--config" });
    auto empty_config_path = parse({ "shinku", "run", "--config", "" });
    auto extra_arg = parse({ "shinku", "run", "extra.toml" });

    expect(!missing.has_value(), "missing subcommand should fail");
    expect(missing.error().code == shinku::cli::CliErrorCode::MissingSubcommand, "missing subcommand code");

    expect(!root_config.has_value(), "root --config should fail");
    expect(root_config.error().code == shinku::cli::CliErrorCode::UnsupportedOption, "root --config code");

    expect(!short_config.has_value(), "run -c should fail");
    expect(short_config.error().code == shinku::cli::CliErrorCode::UnsupportedOption, "run -c code");

    expect(!backend_flag.has_value(), "run --backend should fail");
    expect(backend_flag.error().code == shinku::cli::CliErrorCode::UnsupportedOption, "run --backend code");

    expect(!short_help.has_value(), "-h should fail");
    expect(short_help.error().code == shinku::cli::CliErrorCode::UnsupportedOption, "-h code");

    expect(!run_version.has_value(), "run --version should fail");
    expect(run_version.error().code == shinku::cli::CliErrorCode::UnsupportedOption, "run --version code");

    expect(!duplicate_config.has_value(), "duplicate --config should fail");
    expect(
        duplicate_config.error().code == shinku::cli::CliErrorCode::UnexpectedArgument,
        "duplicate --config code"
    );

    expect(!missing_config_path.has_value(), "missing --config path should fail");
    expect(
        missing_config_path.error().code == shinku::cli::CliErrorCode::MissingConfigPath,
        "missing --config path code"
    );

    expect(!empty_config_path.has_value(), "empty --config path should fail");
    expect(
        empty_config_path.error().code == shinku::cli::CliErrorCode::MissingConfigPath,
        "empty --config path code"
    );

    expect(!extra_arg.has_value(), "unexpected positional arg should fail");
    expect(extra_arg.error().code == shinku::cli::CliErrorCode::UnexpectedArgument, "unexpected arg code");
}

} // namespace

int main() {
    accepts_default_config_path();
    accepts_explicit_config_path();
    accepts_help_and_version_actions();
    rejects_unsupported_forms();

    if (tests_failed != 0) {
        std::cerr << tests_failed << " of " << tests_run << " CLI tests failed\n";
        return EXIT_FAILURE;
    }

    std::cout << tests_run << " CLI tests passed\n";
    return EXIT_SUCCESS;
}

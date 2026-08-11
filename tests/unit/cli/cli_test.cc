// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cli/cli.h"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <filesystem>
#include <variant>
#include <vector>

namespace {

std::expected<shinku::cli::CliResult, shinku::cli::CliError> parse(std::initializer_list<const char*> args) {
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (const char* arg: args)
        argv.push_back(const_cast<char*>(arg));
    return shinku::cli::parse_cli(static_cast<int>(argv.size()), argv.data());
}

} // namespace

TEST_CASE("CLI accepts the default config path") {
    auto result = parse({ "shinku", "run" });

    REQUIRE(result.has_value());
    const auto* command = std::get_if<shinku::cli::CliCommand>(&*result);
    REQUIRE(command != nullptr);
    CHECK(command->config_path == std::filesystem::path("./shinku.toml"));
}

TEST_CASE("CLI accepts an explicit config path") {
    auto result = parse({ "shinku", "run", "--config", "custom.toml" });

    REQUIRE(result.has_value());
    const auto* command = std::get_if<shinku::cli::CliCommand>(&*result);
    REQUIRE(command != nullptr);
    CHECK(command->config_path == std::filesystem::path("custom.toml"));
}

TEST_CASE("CLI leaves config path validation to the config loader") {
    auto result = parse({ "shinku", "run", "--config", "" });

    REQUIRE(result.has_value());
    const auto* command = std::get_if<shinku::cli::CliCommand>(&*result);
    REQUIRE(command != nullptr);
    CHECK(command->config_path.empty());
}

TEST_CASE("CLI accepts help and version actions") {
    auto root_help = parse({ "shinku", "--help" });
    auto run_help = parse({ "shinku", "run", "--help" });
    auto version = parse({ "shinku", "--version" });

    REQUIRE(root_help.has_value());
    CHECK(std::get<shinku::cli::CliAction>(*root_help) == shinku::cli::CliAction::ShowHelp);

    REQUIRE(run_help.has_value());
    CHECK(std::get<shinku::cli::CliAction>(*run_help) == shinku::cli::CliAction::ShowHelp);

    REQUIRE(version.has_value());
    CHECK(std::get<shinku::cli::CliAction>(*version) == shinku::cli::CliAction::ShowVersion);
}

TEST_CASE("CLI rejects unsupported forms") {
    auto missing = parse({ "shinku" });
    auto root_config = parse({ "shinku", "--config", "custom.toml" });
    auto short_config = parse({ "shinku", "run", "-c", "custom.toml" });
    auto backend_flag = parse({ "shinku", "run", "--backend", "ebpf" });
    auto short_help = parse({ "shinku", "-h" });
    auto run_version = parse({ "shinku", "run", "--version" });
    auto duplicate_config = parse({ "shinku", "run", "--config", "a.toml", "--config", "b.toml" });
    auto missing_config_path = parse({ "shinku", "run", "--config" });
    auto extra_arg = parse({ "shinku", "run", "extra.toml" });

    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == shinku::cli::CliErrorCode::MissingSubcommand);
    CHECK_FALSE(missing.error().message.empty());

    REQUIRE_FALSE(root_config.has_value());
    CHECK(root_config.error().code == shinku::cli::CliErrorCode::UnexpectedArgument);
    CHECK_FALSE(root_config.error().message.empty());

    REQUIRE_FALSE(short_config.has_value());
    CHECK(short_config.error().code == shinku::cli::CliErrorCode::UnexpectedArgument);
    CHECK_FALSE(short_config.error().message.empty());

    REQUIRE_FALSE(backend_flag.has_value());
    CHECK(backend_flag.error().code == shinku::cli::CliErrorCode::UnexpectedArgument);
    CHECK_FALSE(backend_flag.error().message.empty());

    REQUIRE_FALSE(short_help.has_value());
    CHECK(short_help.error().code == shinku::cli::CliErrorCode::UnexpectedArgument);
    CHECK_FALSE(short_help.error().message.empty());

    REQUIRE_FALSE(run_version.has_value());
    CHECK(run_version.error().code == shinku::cli::CliErrorCode::UnexpectedArgument);
    CHECK_FALSE(run_version.error().message.empty());

    REQUIRE_FALSE(duplicate_config.has_value());
    CHECK(duplicate_config.error().code == shinku::cli::CliErrorCode::UnexpectedArgument);
    CHECK_FALSE(duplicate_config.error().message.empty());

    REQUIRE_FALSE(missing_config_path.has_value());
    CHECK(missing_config_path.error().code == shinku::cli::CliErrorCode::UnexpectedArgument);
    CHECK_FALSE(missing_config_path.error().message.empty());

    REQUIRE_FALSE(extra_arg.has_value());
    CHECK(extra_arg.error().code == shinku::cli::CliErrorCode::UnexpectedArgument);
    CHECK_FALSE(extra_arg.error().message.empty());
}

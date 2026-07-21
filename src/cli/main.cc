// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_creation.h"
#include "backend/backend_runner.h"
#include "cli/cli.h"
#include "config/diagnostic_sink.h"
#include "config/toml_loader.h"
#include "process_control/process_control.h"
#include "version.h"

#include <print>
#include <utility>

namespace {

void print_cli_error(const shinku::cli::CliError& error) {
    std::println(stderr, "error: {}", error.message);
    std::print(stderr, "{}", shinku::cli::usage_text());
}

} // namespace

int main(int argc, char** argv) {
    auto cli_result = shinku::cli::parse_cli(argc, argv);
    if (!cli_result) {
        print_cli_error(cli_result.error());
        return 2;
    }

    switch (cli_result->action) {
        case shinku::cli::CliAction::ShowHelp:
            std::print("{}", shinku::cli::usage_text());
            return 0;
        case shinku::cli::CliAction::ShowVersion:
            std::println("shinku {}", SHINKU_VERSION);
            return 0;
        case shinku::cli::CliAction::Run:
            break;
    }

    if (!cli_result->command.has_value()) {
        std::println(stderr, "error: run command is missing");
        return 2;
    }

    shinku::config::StderrDiagnosticSink sink;
    auto config = shinku::config::load_config(cli_result->command->config_path, sink);
    if (!config)
        return 1;

    auto& process_control = shinku::process_control::ProcessControl::instance();
    auto signal_handlers = shinku::process_control::ProcessControl::install_signal_handlers();
    if (!signal_handlers) {
        std::println(stderr, "error: {}", signal_handlers.error().message);
        return 1;
    }

    auto selected_backend = shinku::backend::make_backend(*config);
    if (!selected_backend) {
        std::println(stderr, "error: {}", selected_backend.error().message);
        return 1;
    }

    shinku::backend::BackendRunner runner(std::move(*selected_backend));
    auto run_result = runner.run(process_control);
    if (!run_result) {
        std::println(stderr, "error: {}", run_result.error().message);
        return 1;
    }

    return 0;
}

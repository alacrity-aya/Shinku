// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cli/cli.h"
#include "config/diagnostic_sink.h"
#include "config/legacy_env_adapter.h"
#include "config/toml_loader.h"
#include "process_control/process_control.h"
#include "runtime/legacy_ebpf_runner.h"
#include "version.h"

#include <print>

namespace {

void print_cli_error(const shinku::cli::CliError& error) {
    std::println(stderr, "error: {}", error.message);
    std::print(stderr, "{}", shinku::cli::usage_text());
}

int shutdown_requested(void* user_data) {
    const auto* process_control = static_cast<const shinku::process_control::ProcessControl*>(user_data);
    return process_control->shutdown_requested() ? 1 : 0;
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

    shinku::config::StderrDiagnosticSink sink;
    auto config = shinku::config::load_config(cli_result->command->config_path, sink);
    if (!config)
        return 1;

    auto legacy_env = shinku::config::to_legacy_env(*config);
    if (!legacy_env) {
        sink.error(legacy_env.error());
        return 1;
    }

    auto& process_control = shinku::process_control::ProcessControl::instance();
    auto signal_handlers = process_control.install_signal_handlers();
    if (!signal_handlers) {
        std::println(stderr, "error: {}", signal_handlers.error().message);
        return 1;
    }

    return shinku_run_legacy_ebpf(&*legacy_env, shutdown_requested, &process_control);
}

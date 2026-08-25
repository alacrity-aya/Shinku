// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "config_error.h"

namespace shinku::config {

/**
 * @brief Abstract sink for operator-facing configuration diagnostics.
 *
 * The TOML loader emits warnings (non-fatal) and errors (fatal) through this
 * interface so the host can route them to whatever output channel it prefers.
 */
class DiagnosticSink {
public:
    virtual ~DiagnosticSink() = default;

    /// @brief Emit a non-fatal configuration warning.
    virtual void warning(const ConfigWarning& warning) = 0;
    /// @brief Emit a fatal configuration error.
    virtual void error(const ConfigError& error) = 0;
};

/**
 * @brief A @ref DiagnosticSink that writes warnings and errors to standard error.
 */
class StderrDiagnosticSink final : public DiagnosticSink {
public:
    void warning(const ConfigWarning& warning) override;
    void error(const ConfigError& error) override;
};

} // namespace shinku::config

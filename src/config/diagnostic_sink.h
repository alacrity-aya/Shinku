// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "config_error.h"

namespace shinku::config {

class DiagnosticSink {
public:
    virtual ~DiagnosticSink() = default;

    virtual void warning(const ConfigWarning& warning) = 0;
    virtual void error(const ConfigError& error) = 0;
};

class StderrDiagnosticSink final : public DiagnosticSink {
public:
    void warning(const ConfigWarning& warning) override;
    void error(const ConfigError& error) override;
};

} // namespace shinku::config

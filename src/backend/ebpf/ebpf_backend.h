// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend.h"
#include "backend/ebpf/ebpf_native_session.h"
#include "config/config.h"

#include <memory>

namespace shinku::backend::ebpf {

class EbpfBackend final: public Backend {
public:
    EbpfBackend(
        config::EbpfConfig ebpf_config,
        [[maybe_unused]] config::CacheConfig cache_config,
        std::unique_ptr<EbpfNativeSession> native_session
    );
    ~EbpfBackend() override;

protected:
    [[nodiscard]] std::expected<void, BackendError> probe() override;
    [[nodiscard]] std::expected<void, BackendError> start() override;
    [[nodiscard]] std::expected<PollStatus, BackendError> poll() override;
    [[nodiscard]] std::expected<void, BackendError> stop() override;

private:
    struct CleanupWorker;

    config::EbpfConfig config_;
    std::unique_ptr<EbpfNativeSession> native_session_;
    std::unique_ptr<CleanupWorker> cleanup_worker_;
};

} // namespace shinku::backend::ebpf

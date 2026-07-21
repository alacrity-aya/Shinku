// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend.h"
#include "backend/ebpf/ebpf_loader_config.h"
#include "backend/ebpf/ebpf_loader_ops.h"
#include "config/config.h"

#include <memory>

struct bpf_ctx;

namespace shinku::backend::ebpf {

class EbpfBackend final: public Backend {
public:
    EbpfBackend(
        config::EbpfConfig ebpf_config,
        [[maybe_unused]] config::CacheConfig cache_config,
        const EbpfLoaderOps& ops,
        void* ops_context = nullptr
    );
    ~EbpfBackend() override;

    [[nodiscard]] std::expected<void, BackendError> probe() override;
    [[nodiscard]] std::expected<void, BackendError> start() override;
    [[nodiscard]] std::expected<PollStatus, BackendError> poll_once() override;
    [[nodiscard]] std::expected<void, BackendError> stop() override;

private:
    EbpfLoaderConfig loader_config_;
    const EbpfLoaderOps* ops_;
    void* ops_context_;
    std::unique_ptr<bpf_ctx> bpf_context_;
    bool loader_resources_active_ = false;
};

} // namespace shinku::backend::ebpf

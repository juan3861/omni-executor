# Known Operational Boundaries & Honest Limitations (Radical Truth)

1. **Cloud Sandboxes & SaaS APIs (`E2B`, `Exa`):** Require explicit operator API keys (`E2B_API_KEY`, `EXA_API_KEY`); when unset, the kernel honestly reports local fallback mode.
2. **Local GPU (`RX 580`):** Vulkan/llama.cpp `-ngl 99` is constitutionally blocked to prevent TDR driver crashes; local `rotor-llm` is consumed strictly via read-only HTTP (`:3700`).
3. **Physical Actuation (`ExecutionRealm.REQUIRES_PHYSICAL_ACTUATION`):** Digital verification never claims physical-world actuation without external sensor telemetry.

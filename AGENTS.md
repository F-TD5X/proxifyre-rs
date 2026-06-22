# Proxifyre Developer Guidelines

This document provides comprehensive instructions for agents and developers working on the `proxifyre` codebase. 
It covers build commands, code style, testing protocols, and architectural conventions.

## 1. Environment & Build System

The project is a Rust application targeting Windows, developed on Linux. It uses `cargo-xwin` for cross-compilation.

### key Commands

| Action | Command | Description |
|--------|---------|-------------|
| **Check** | `cargo xwin check --target x86_64-pc-windows-msvc` | Fast compilation check. |
| **Build (Dev)** | `cargo xwin build --target x86_64-pc-windows-msvc` | Build debug binary. |
| **Build (Release)** | `cargo xwin build --target x86_64-pc-windows-msvc --release` | Build optimized release binary. |
| **Test (All)** | `cargo xwin test --target x86_64-pc-windows-msvc` | Run all unit and integration tests. |
| **Test (Single)** | `cargo xwin test --target x86_64-pc-windows-msvc -- test_name_here` | Run a specific test case by name. |
| **Lint** | `cargo xwin clippy --target x86_64-pc-windows-msvc` | Run linter (Fix with `--fix`). |
| **Format** | `cargo fmt` | Format code using `rustfmt`. |

**Note:** On native Windows environments, standard `cargo build` / `cargo test` commands apply.

## 2. Project Structure

```text
src/
├── main.rs                 # Binary entry point; setup for config, logging, and TUI.
├── config.rs               # Configuration loading (Serde) and default values.
├── app.rs                  # Main application loop and logic.
├── tui.rs                  # Terminal User Interface (Ratatui + Crossterm).
├── logging.rs              # Logging configuration.
├── proxy/                  # Proxy protocol implementations.
│   ├── mod.rs              # Module definitions.
│   ├── socks5.rs           # SOCKS5 client/server logic.
│   └── transparent_proxy.rs # System-level transparent proxying.
├── router/                 # Packet routing logic.
│   ├── mod.rs
│   ├── flow.rs             # Flow tracking.
│   ├── packet.rs           # Packet parsing/manipulation (smoltcp).
│   └── adapter.rs          # Network adapter abstraction.
└── windows/                # Windows-specific integrations (unsafe Win32 API).
    ├── mod.rs
    ├── process.rs          # Process information/metadata.
    └── stats.rs            # System statistics.
```

## 3. Code Style & Conventions

Adhere strictly to standard Rust conventions.

### Formatting & Naming
- **Indentation:** 4 spaces. No tabs.
- **Line Length:** 100 characters (soft limit), 120 (hard limit).
- **Casing:**
  - `snake_case`: Modules, functions, methods, local variables.
  - `CamelCase`: Structs, Enums, Traits.
  - `SCREAMING_SNAKE_CASE`: Constants, Statics.
- **Files:** One major struct/trait per file usually, or grouped logic.

### Imports
Group imports in the following order, separated by a blank line:
1.  Standard Library (`use std::...`)
2.  Third-party Crates (`use tokio::...`, `use serde::...`)
3.  Local Modules (`use crate::config::...`)

Example:
```rust
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpStream;

use crate::proxy::Socks5Dialer;
```

### Error Handling
- **Application Layer (`main.rs`, `app.rs`):** Use `anyhow::Result` for flexible error propagation.
- **Library/Modules (`src/proxy/`, `src/router/`):** Use `std::io::Result` or define specific `thiserror` enums if specific handling is required.
- **Context:** When using `anyhow`, always attach context: `.context("Failed to initialize TUI")?`.

### Async/Await
- Use `tokio` for async runtime.
- Prefer `async fn` over returning `BoxFuture`.
- Use `tokio::sync` primitives (`Mutex`, `RwLock`, `mpsc`) over `std::sync` in async contexts.

### Comments & Documentation
- **Doc Comments (`///`):** Required for all `pub` structs, enums, and functions. Explain *what* it does.
- **Implementation Comments (`//`):** Explain *why* complex logic exists. Do not explain obvious code.
- **TODOs:** Format as `// TODO(user): Description`.

## 4. Testing Guidelines

### Unit Tests
- Place unit tests in the same file as the code, within a `#[cfg(test)]` module at the bottom.
- Import `super::*` to access private members.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socks5_handshake() {
        // ...
    }
}
```

### Integration Tests
- Place in `tests/` directory (create if missing).
- Treat the crate as an external dependency (`use proxifyre::...`).

### Mocks & Fakes
- Prefer using Traits for dependencies to allow mocking.
- For IO, use `std::io::Cursor` or `tokio_test::io::Builder` to mock streams.

## 5. Specific Implementation details

### Windows Integration
- All Windows-specific code must be in `src/windows/`.
- Use `windows` crate.
- Mark `unsafe` blocks clearly and verify safety invariants.

### Packet Processing
- Uses `smoltcp` for packet parsing.
- Critical path: Avoid memory allocation in the hot loop (packet routing).
- Use `log::trace!` for per-packet logging (disabled by default).

### TUI
- Uses `ratatui`.
- Separate rendering logic from state updates.
- Ensure the UI loop does not block the networking loop.

## 6. Workflow for Agents

1.  **Analyze**: Run `ls -R` or `glob` to find relevant files. Read `Cargo.toml` to check dependencies.
2.  **Verify State**: Run `cargo xwin check ...` to ensure the codebase is clean before changes.
3.  **Implement**: Make changes.
4.  **Test**:
    - Add a test case for the new logic.
    - Run `cargo xwin test ... -- new_test_name` to verify.
    - Run `cargo xwin check ...` to ensure no compilation errors.
5.  **Refine**: Run `cargo fmt` and `cargo xwin clippy ...`.

## 7. Configuration (`config.toml`)
- Do not commit secrets.
- Use `config.example.toml` as a template.
- Structure:
  ```toml
  [service]
  proxies = [
    { app_names = ["firefox.exe"], endpoint = "127.0.0.1:1080" }
  ]
  ```

---
*Generated for coding agents. Adhere strictly to these guidelines.*

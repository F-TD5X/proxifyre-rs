This is a rust Application level proxy. Which implements something like [proxifyre](https://github.com/wiresock/ndisapi-go/tree/main/examples/proxifyre)

What is has:

- IPv4/IPv6 TCP/UDP support.
- A simple ratatui to show the connection status.

## How to use
1. Move the `config.example.toml` to `config.toml`
2. Install the driver which you can get from [ndisapi](https://github.com/wiresock/ndisapi)
3. Update the config.toml and run the executable as admin.

## How to build

> I'm code it on linux and test it on windows vm. So build it on windows should be pretty simple with `cargo build --release`.

1. Setup [cargo-xwin](https://github.com/rust-cross/cargo-xwin) by following it's usage doc.
2. Build this project by `cargo xwin build --release --target=x86_64-pc-windows-msvc`

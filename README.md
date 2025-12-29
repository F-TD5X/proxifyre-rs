This is a rust Application level proxy. Which implements something like [proxifyre](https://github.com/wiresock/ndisapi-go/tree/main/examples/proxifyre)

And with a ratatui to show the connection status.

## How to use
Update the config.toml and run the executable as admin.

## How to build

> I'm code it on linux and test it on windows vm. So build it on windows is pretty simple with `cargo build --release`

1. Setup cargo-xwin by following it's usage doc.
2. Build this project by `cargo xwin build --release --target=x86_64-pc-windows-msvc`

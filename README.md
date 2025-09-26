# RADIUS Server in Rust

A high-performance, async RADIUS server implementation written in Rust.

## Features

- **Async/Await**: Built with Tokio for high concurrency
- **Authentication**: PAP authentication support with pluggable backends
- **Accounting**: Session tracking and accounting
- **Configuration**: YAML-based configuration
- **Logging**: Structured logging with tracing
- **Modular**: Plugin architecture for authentication backends

## Technology Stack

- **Core**: `radius` crate for RADIUS protocol handling
- **Async Runtime**: `tokio` for async operations
- **Configuration**: `serde` + `serde_yaml` for config management
- **CLI**: `clap` for command-line interface
- **Logging**: `tracing` + `tracing-subscriber` for structured logging
- **Error Handling**: `anyhow` + `thiserror` for error management

## Project Structure

```
src/
├── auth/           # Authentication module
│   ├── authenticator.rs
│   └── backend.rs  # Authentication backends
├── config/         # Configuration management
├── handlers/       # Protocol handlers
│   ├── auth_handler.rs
│   └── acct_handler.rs
├── models/         # Data models
│   ├── client.rs
│   ├── user.rs
│   └── session.rs
└── main.rs         # Server entry point

config/
└── config.yaml     # Server configuration

examples/
└── simple_client.rs # Example RADIUS client
```

## Quick Start

### 1. Build the project
```bash
cargo build --release
```

### 2. Create a dictionary file
You'll need a RADIUS dictionary file. You can use the standard FreeRADIUS dictionary or create a minimal one.

### 3. Run the server
```bash
cargo run -- --config config/config.yaml
```

### 4. Test with the example client
```bash
cargo run --example simple_client
```

## Configuration

Edit `config/config.yaml` to configure:

- Server bind address and ports
- Client definitions with shared secrets
- Logging settings
- Authentication backends

## Authentication Backends

Currently supports:
- **Memory Backend**: In-memory user store (for testing)

Planned backends:
- **LDAP**: Active Directory/LDAP integration
- **Database**: SQL database backends
- **File**: File-based user stores

## Usage Examples

### Basic Authentication Test
```bash
# Start the server
cargo run

# In another terminal, test authentication
cargo run --example simple_client
```

### Custom Configuration
```bash
cargo run -- --config /path/to/your/config.yaml --log-level debug
```

## Development

### Running Tests
```bash
cargo test
```

### Adding New Authentication Backends

1. Implement the `AuthBackend` trait in `src/auth/backend.rs`
2. Register your backend in the server initialization
3. Update configuration to support your backend type

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License.
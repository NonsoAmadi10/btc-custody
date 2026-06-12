# Contributing to BTC Custody

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/btc-custody.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `go test ./...`
6. Commit with a clear message
7. Push and open a Pull Request

## Development Setup

```bash
# Install dependencies
brew install go softhsm  # macOS
# or
apt install golang softhsm2  # Linux

# Run tests
go test ./...

# Run with race detector
go test -race ./...

# Run linter
golangci-lint run
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Add tests for new functionality
- Update documentation if needed
- Keep commits atomic and well-described

## Testing

- All new code must have tests
- Run `go test ./...` before submitting
- Security-related changes should include threat model tests

## Areas for Contribution

- [ ] Improve test coverage
- [ ] Add more policy rules
- [ ] Network transport layer (gRPC/libp2p)
- [ ] Better error messages
- [ ] Documentation improvements
- [ ] Performance optimizations

## Security

If you discover a security vulnerability, please email directly rather than opening a public issue.

## Questions?

Open an issue for discussion before starting large changes.

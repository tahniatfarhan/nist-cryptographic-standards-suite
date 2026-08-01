# Contributing to NIST Cryptographic Standards Suite

Thank you for your interest in contributing to this educational cryptography demonstration suite!

## Development & Test Setup

1. **Clone & Install Dependencies**:
   ```bash
   git clone https://github.com/tahniatfarhan/nist-cryptographic-standards-suite.git
   cd nist-cryptographic-standards-suite
   pip install -e .[dev]
   ```

2. **Execute Pytest Suite**:
   ```bash
   pytest -v
   ```

3. **Commit Guidelines**:
   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(ciphers): add AES-GCM tag verification test`
   - `fix(pki): resolve X.509 validity range formatting`
   - `docs(readme): add sequence diagram for hybrid encryption`

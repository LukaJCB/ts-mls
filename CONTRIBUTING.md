# Contributing to ts-mls

Thank you for your interest in contributing to ts-mls! This document outlines the development setup and the checks that need to pass for contributions to be accepted.

## Repository Setup

### Prerequisites

- Node.js (version 19 or higher required)
- npm (comes with Node.js)

> **Note**: Node.js 19+ is required because this project uses the Web Crypto API (`crypto.subtle`) which is only available as a global object starting from Node.js 19.

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/LukaJCB/ts-mls.git
   cd ts-mls
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

   Note: The `postinstall` script will automatically run `patch-package` to apply a necessary patch to the hpke-js dependency.

### Project Structure

- `src/` - Main TypeScript source code
- `test/` - Test files including unit tests and scenario tests
- `docs/` - Documentation files with code examples
- `test_vectors/` - MLS provided test vector files

## Development Workflow

### Building the Project

To build the TypeScript code:

```bash
npm run build
```

This compiles the TypeScript source code in `src/` to JavaScript in `dist/`.

### Running Tests

To run all tests:

```bash
npm run test
```

To run a specific test by name:

```bash
npm run test -- --t "Large Group, Full Lifecycle"
```

The test suite contains:

- The `/codec` directory with unit tests for the codecs defined in the MLS spec (mostly roundtrip tests that encode and then decode a value)
- The `/crypto` directory with unit tests for various cryptographic operations
- The `/scenario` directory with scenario tests that simulate real-world MLS usage patterns
- The `/test_vectors` directory for MLS provided test vector validation

### Code Formatting

The project uses Prettier for code formatting.

To format all files:

```bash
npm run format
```

To check if files are properly formatted:

```bash
npm run format:check
```

### Documentation Verification

To verify that code examples in documentation compile correctly:

```bash
npm run verify-docs
```

This checks all markdown files in the `docs/` directory and the `README.md` for valid TypeScript code examples.

### Dependency Analysis

To check for circular dependencies:

```bash
npx run verify-madge
```

This ensures the codebase doesn't have circular import dependencies.

## Verification Process

Before submitting a pull request, all checks must pass. The complete verification process can be run with:

```bash
npm run verify
```

This command runs all the previously mentioned checks in sequence:

1. **Build Check** (`npm run build`)
2. **Format Check** (`npm run format:check`)
3. **Documentation Verification** (`npm run verify-docs`)
4. **Circular Dependency Check** (`npm run verify-madge`)
5. **Test Suite** (`npm run test`)

## Making Changes

### Code Style Guidelines

- Use TypeScript for all new code
- Follow the existing code style and formatting
- Add type annotations for any `export`ed function or value.

### Testing

- Add unit tests for new functionality
- Ensure all existing tests continue to pass

### Documentation

- Update relevant documentation files
- Ensure code examples compile and run correctly

## Submitting Changes

1. Create a feature branch from the main branch
2. Make your changes following the guidelines above
3. Run the complete verification process: `npm run verify`
4. Ensure all checks pass
5. Submit a pull request with a clear description of your changes

Thank you for contributing to ts-mls!

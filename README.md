# Rusty Merkle Tree

Implementation of a dynamic Merkle Tree in Rust. This project is part of the **LambdaClass Engineering Residency** learning path.

## Project Structure

This library provides an implementation capable of:
- Building a Merkle Tree from an array.
- Generating a proof that it contains an element.
- Verifying that a given hash is contained in it.
- Dynamically adding elements after the tree is built.

## Requirements

- Rust (managed via `asdf` as specified in `.tool-versions`)
- Make

## Usage

A `Makefile` is provided with standard targets to interact with the project:

- `make build`: Compiles the project.
- `make test`: Runs the test suite.
- `make fmt`: Checks code formatting.
- `make check`: Runs `cargo check`.

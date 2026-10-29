# Woody Woodpacker

My implementation of the **42 Woody Woodpacker project**, stored in the `ELF_Packer` repository. It explores executable formats, code encryption, and a small assembly loader that restores the packed code before returning control to the original program.

The newer implementation lives in [new_woody](new_woody). It produces a separate packed executable and leaves the input file unchanged.

## Features

- Format handlers for Linux ELF64, Linux ELF32, and Windows PE64.
- XOR-based code encryption using a rotating key.
- Random key generation from `/dev/urandom`, with an optional decimal key argument.
- Assembly stubs that decrypt the code and transfer control to the original entry point.
- The `....WOODY....` banner before the original program runs.
- Separate output files: `woody` for ELF inputs and `woody.exe` for PE inputs.

ELF64 was built and tested with the included hello-world source on Linux x86-64. ELF32 and PE64 handlers are present, but their runtime behavior was not verified during documentation checks. This implementation does not provide general executable compression or strong cryptographic protection.

## Repository layout

| Path | Contents |
| --- | --- |
| [new_woody](new_woody) | Newer implementation with a shared format-handler interface |
| [new_woody/src](new_woody/src) | ELF32, ELF64, PE64, and key-parsing code |
| [new_woody/stubs](new_woody/stubs) | Assembly loaders and the Windows message helper |
| [woody](woody) | Earlier ELF64 implementation |
| [woody/bonus](woody/bonus) | Earlier bonus experiments |
| [woody/test](woody/test) | Small encryption and loader experiments |

## Requirements

Build on **Linux x86-64** with GCC, Make, and NASM. The complete build also requires MinGW-w64 tools: `x86_64-w64-mingw32-gcc`, `x86_64-w64-mingw32-ld`, and `x86_64-w64-mingw32-objcopy` for the PE64 loader.

Running ELF32 output requires a compatible 32-bit runtime; PE64 output requires a suitable Windows environment. Neither is needed for the ELF64 example below.

## Build

There is no root Makefile. Build the newer version:

```sh
cd new_woody
make
```

For an ELF64-only build without the MinGW tools, select just the packer and ELF64 loader targets:

```sh
make woody_woodpacker stubs/stub_elf64.bin
```

The full build also assembles the ELF32 and PE64 loaders. Run the packer from `new_woody/`: loader paths are relative to the current directory.

## Usage

```text
./woody_woodpacker <target_binary> [encryption_key]
```

From `new_woody/`, build and pack the included demonstration:

```sh
cc hello.c -o demo
./woody_woodpacker demo
./woody
```

Verified output from the packed demo:

```text
....WOODY....
Hello, Woody!!
```

To supply a decimal key instead of generating one:

```sh
./woody_woodpacker demo 123456789
```

Each invocation overwrites the corresponding output file in the current directory. Choose an input name other than `woody` or `woody.exe` to keep the input separate from the output.

## Limitations and cleanup

- The ELF handlers depend on sufficient padding after the executable segment for their loader. Arbitrary binaries are not guaranteed to work.
- File validation and layout handling are experimental; the successful demo does not establish compatibility with all executables.
- The earlier `woody/` implementation currently fails to compile because of an incomplete condition in `funcs/find_text_segment.c`.
- In `new_woody/`, `make clean` removes objects, generated loader files, and `woody`; `make fclean` also removes `woody_woodpacker`. The current cleanup rules leave `woody.exe` and manually created demo files in place.

## Concepts practiced

Executable headers, segments and sections, virtual addresses versus file offsets, memory mapping, entry points, position-independent assembly, register preservation, cross-compilation, and C/assembly integration.

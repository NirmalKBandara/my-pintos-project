# Pintos Operating System Project

This repository contains the source code for the Pintos operating system, a teaching OS for the x86 architecture.

## Prerequisites

### Option 1: Docker (Recommended)

The easiest way to get started is using Docker, which provides a consistent, isolated environment without needing to install dependencies or configure paths.

**Requirements:**
*   [Docker](https://docs.docker.com/get-docker/) installed on your system
*   [Docker Compose](https://docs.docker.com/compose/install/) (usually included with Docker Desktop)

### Option 2: Native Linux/WSL

If you prefer not to use Docker, you can set up the environment manually in a Linux environment. If you are on Windows, you **must** use [WSL (Windows Subsystem for Linux)](https://docs.microsoft.com/en-us/windows/wsl/install) or a Linux Virtual Machine.

**Requirements:**
*   `make`
*   `perl`
*   `qemu-system-i386` (or `bochs`)
*   `gcc` (host compiler for utilities)
*   `gdb` (optional, for debugging)

## Setup

### Option 1: Using Docker (Recommended)

1.  **Clone the repository**:
    ```bash
    git clone <your-repo-url>
    cd my-pintos-project
    ```

2.  **Build the Docker image**:
    ```bash
    docker-compose build
    ```

3.  **Start the container**:
    ```bash
    docker-compose run --rm pintos
    ```
    
    This will start an interactive shell inside the container with all dependencies pre-configured.

4.  **You're ready to go!** The toolchain and utilities are already in your PATH. You can now proceed to [Building Pintos](#building-pintos).

### Option 2: Manual Setup (Linux/WSL)

1.  **Clone the repository**:
    ```bash
    git clone <your-repo-url>
    cd my-pintos-project
    ```

2.  **Configure Paths**:
    You need to add the provided toolchain and utility scripts to your `PATH`.
    Add the following lines to your shell configuration file (e.g., `~/.bashrc` or `~/.zshrc`), adjusting the path to where you cloned the repository:

    ```bash
    # Adjust this path to match your actual project location
    export PINTOS_ROOT=/path/to/my-pintos-project

    # Add toolchain binaries (compiler, linker, etc.)
    export PATH=$PINTOS_ROOT/toolchain/x86_64/bin:$PATH

    # Add Pintos utility scripts
    export PATH=$PINTOS_ROOT/pintos/src/utils:$PATH
    ```

    Reload your shell configuration:
    ```bash
    source ~/.bashrc
    ```

3.  **Compile Utilities**:
    The `pintos` utility script may need some helper binaries compiled.
    ```bash
    cd pintos/src/utils
    make
    ```

## Building Pintos

Pintos is built in subdirectories corresponding to different projects (Threads, User Programs, VM, File System).

To build the kernel for the **Threads** project (usually the starting point):

```bash
cd pintos/src/threads
make
```

This will create a `build` directory containing the kernel image (`kernel.bin`) and other object files.

## Running Pintos

Use the `pintos` utility script to run the operating system in a simulator (QEMU by default).

**Example: Run the alarm-multiple test**
```bash
cd pintos/src/threads/build
pintos --qemu -- -q run alarm-multiple
```

*   `--qemu`: Specifies the simulator.
*   `--`: Separates `pintos` script options from kernel arguments.
*   `-q`: Tells the kernel to power off after the run.
*   `run alarm-multiple`: Arguments passed to the kernel to run the specific test.

**Example: Run all tests**
```bash
cd pintos/src/threads/build
make check
```

## Debugging

You can debug the kernel using GDB.

1.  **Start Pintos in debug mode**:
    ```bash
    cd pintos/src/threads/build
    pintos --gdb --qemu -- -q run alarm-multiple
    ```
    This will pause the simulation and wait for a GDB connection.

2.  **Attach GDB**:
    Open a new terminal window:
    ```bash
    cd pintos/src/threads/build
    i386-elf-gdb kernel.o
    ```
    (Note: `i386-elf-gdb` is part of the provided toolchain).

    Inside GDB, connect to the simulator:
    ```gdb
    target remote localhost:1234
    ```

    You can now set breakpoints and step through the kernel code.

### Debugging with Docker

If using Docker, you'll need two terminal windows:

**Terminal 1 - Start Pintos in debug mode:**
```bash
docker-compose run --rm pintos bash -c "cd build && pintos --gdb --qemu -- -q run alarm-multiple"
```

**Terminal 2 - Attach GDB:**
```bash
docker-compose run --rm pintos i386-elf-gdb build/kernel.o -ex "target remote host.docker.internal:1234"
```

> **Note:** On Linux, replace `host.docker.internal` with `172.17.0.1` (Docker's default bridge network gateway).

## Directory Structure

*   `pintos/src`: Source code for the OS.
    *   `threads/`: Source for the threads project.
    *   `userprog/`: Source for the user programs project.
    *   `vm/`: Source for the virtual memory project.
    *   `filesys/`: Source for the file system project.
    *   `utils/`: Utilities for running and testing Pintos.
*   `toolchain/`: Pre-built cross-compiler toolchain for x86.

## Docker Workflow Tips

If you're using Docker, here are some helpful tips:

**Running commands without entering the container:**
```bash
# Build the kernel
docker-compose run --rm pintos make

# Run tests
docker-compose run --rm pintos bash -c "cd build && make check"

# Run a specific test
docker-compose run --rm pintos bash -c "cd build && pintos --qemu -- -q run alarm-multiple"
```

**Keeping the container running:**
```bash
# Start the container in the background
docker-compose up -d

# Execute commands in the running container
docker exec -it pintos-dev bash

# Stop the container when done
docker-compose down
```

**Rebuilding after changes:**
If you modify the Dockerfile or need to refresh the image:
```bash
docker-compose build --no-cache
```


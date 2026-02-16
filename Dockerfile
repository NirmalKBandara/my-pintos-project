FROM ubuntu:20.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    perl \
    gdb \
    qemu-system-x86 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /pintos

# Copy the entire project
COPY . /pintos

# Add toolchain and utilities to PATH
ENV PATH="/pintos/toolchain/x86_64/bin:/pintos/pintos/src/utils:${PATH}"

# Build the utilities
WORKDIR /pintos/pintos/src/utils
RUN make

# Set default working directory to threads
WORKDIR /pintos/pintos/src/threads

# Default command opens a bash shell
CMD ["/bin/bash"]

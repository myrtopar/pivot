FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive 

RUN dpkg --add-architecture i386

RUN apt-get update && \
    apt-get install -y \
    python3 python3-pip gcc-multilib gdb libc6:i386 strace \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir pwntools && \
    pip3 install pytest

RUN mkdir -p /mnt/binaries

ENV PATH="/mnt/binaries:$PATH"

WORKDIR /app

CMD ["bash"]

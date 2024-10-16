FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive 
ENV PATH="/mnt/binaries:$PATH"

RUN dpkg --add-architecture i386

RUN apt-get update && \
    apt-get install -y \
    python3 python3-pip \
    gcc-multilib gdb libc6:i386 \
    strace \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir pwntools pytest

RUN mkdir -p /mnt/binaries

COPY /binaries/vuln /mnt/binaries/vuln
COPY /binaries/iwconfig_real /mnt/binaries/iwconfig_real
COPY /binaries/ncompress /mnt/binaries/ncompress
COPY /binaries/word-list-compress /mnt/binaries/word-list-compress

RUN chmod +x /mnt/binaries/*

WORKDIR /app

CMD ["bash"]

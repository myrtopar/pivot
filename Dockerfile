FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive 
ENV PATH="/mnt/binaries:$PATH"

RUN dpkg --add-architecture i386

COPY requirements.txt requirements.txt

RUN apt-get update && \
    apt-get install -y \
    python3 python3-pip \
    gcc-multilib gdb libc6:i386 \
    strace \
    && rm -rf /var/lib/apt/lists/*

RUN pip install -r requirements.txt

RUN mkdir -p /mnt/binaries

COPY /binaries/vuln /mnt/binaries/vuln
COPY /binaries/iwconfig_real /mnt/binaries/iwconfig_real
# COPY --from=ethan42/ncompress /workdir/ncompress /mnt/binaries/ncompress
COPY /binaries/ncompress /mnt/binaries/ncompress
COPY /binaries/word-list-compress /mnt/binaries/word-list-compress

RUN chmod +x /mnt/binaries/*

WORKDIR /app

CMD ["bash"]

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

COPY --from=myrtopar/vuln:latest /mnt/bin/vuln /mnt/binaries/vuln
COPY --from=ethan42/iwconfig:latest /usr/sbin/iwconfig_real /mnt/binaries/iwconfig
COPY --from=ethan42/ncompress:1 /workdir/ncompress /mnt/binaries/ncompress
COPY --from=ethan42/aspell:1 /workdir/aspell-0.50.5/prog/word-list-compress /mnt/binaries/aspell
COPY --from=myrtopar/june:latest /mnt/bin/june /mnt/binaries/june
COPY --from=myrtopar/july:latest /mnt/bin/july /mnt/binaries/july

RUN chmod +x /mnt/binaries/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]

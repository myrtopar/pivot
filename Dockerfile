FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/mnt/binaries:$PATH"

RUN dpkg --add-architecture i386

RUN apt-get update && \
    apt-get install -y \
    python3.11 python3-pip python3.11-venv \
    gcc-multilib gdb libc6:i386 \
    strace \
    file \
    xxd \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app
   
#set up the virtual environment path
ENV VIRTUAL_ENV=/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

#create the virtual environment
RUN python3.11 -m venv $VIRTUAL_ENV
#upgrade to the correct pip and setuptools versions, the others are deprecated
RUN pip install --upgrade pip setuptools

COPY requirements.txt .
COPY pyproject.toml .
COPY src/ ./src/

RUN pip install -r requirements.txt

RUN pip install -e . && pip install .[dev]
RUN rm -rf build/ *.egg-info/ 
RUN rm -f requirements.txt pyproject.toml

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /mnt/binaries

COPY --from=myrtopar/vuln:latest /mnt/bin/vuln /mnt/binaries/vuln
COPY --from=ethan42/iwconfig:latest /usr/sbin/iwconfig_real /mnt/binaries/iwconfig
COPY --from=ethan42/ncompress:1 /workdir/ncompress /mnt/binaries/ncompress
COPY --from=myrtopar/aspell:latest /mnt/bin/aspell /mnt/binaries/aspell

COPY --from=myrtopar/june:latest /mnt/bin/june_real /mnt/binaries/june_real
COPY --from=myrtopar/june:latest /mnt/bin/june_wrapper /mnt/binaries/june
COPY --from=myrtopar/june:latest /mnt/bin/junealt_real /mnt/binaries/junealt_real
COPY --from=myrtopar/june:latest /mnt/bin/junealt_wrapper /mnt/binaries/junealt

COPY --from=myrtopar/july:latest /mnt/bin/july /mnt/binaries/july

RUN chmod +x /mnt/binaries/*

COPY crash_inputs /crash_inputs
COPY --from=myrtopar/june:latest /crash_inputs/june_input /crash_inputs/june_input
COPY --from=myrtopar/june:latest /crash_inputs/june_alt_input /crash_inputs/junealt_input


ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]

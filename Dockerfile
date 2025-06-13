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

#copying binaries / benchmarks
COPY --from=myrtopar/june:latest /mnt/bin/june_real /mnt/binaries/june_real
COPY --from=myrtopar/june:latest /mnt/bin/june_wrapper /mnt/binaries/june
COPY --from=myrtopar/june:latest /mnt/bin/junealt_real /mnt/binaries/junealt_real
COPY --from=myrtopar/june:latest /mnt/bin/junealt_wrapper /mnt/binaries/junealt
COPY --from=myrtopar/july:latest /mnt/bin/july_real /mnt/binaries/july_real
COPY --from=myrtopar/july:latest /mnt/bin/july /mnt/binaries/july
COPY --from=myrtopar/vuln:latest /mnt/bin/vuln_real /mnt/binaries/vuln_real
COPY --from=myrtopar/vuln:latest /mnt/bin/vuln /mnt/binaries/vuln
COPY --from=myrtopar/aspell:latest /mnt/bin/aspell_real /mnt/binaries/aspell_real
COPY --from=myrtopar/aspell:latest /mnt/bin/aspell /mnt/binaries/aspell
COPY --from=myrtopar/iwconfig:latest /mnt/bin/iwconfig_real /mnt/binaries/iwconfig_real
COPY --from=myrtopar/iwconfig:latest /mnt/bin/iwconfig /mnt/binaries/iwconfig
COPY --from=myrtopar/ncompress:latest /mnt/bin/ncompress_real /mnt/binaries/ncompress_real
COPY --from=myrtopar/ncompress:latest /mnt/bin/ncompress /mnt/binaries/ncompress
COPY --from=myrtopar/stacksix:latest /mnt/bin/stacksix_real /mnt/binaries/stacksix_real
COPY --from=myrtopar/stacksix:latest /mnt/bin/stacksix /mnt/binaries/stacksix
COPY --from=myrtopar/picoctf_bof:latest /mnt/bin/picoctf_real /mnt/binaries/picoctf_bof_real
COPY --from=myrtopar/picoctf_bof:latest /mnt/bin/picoctf /mnt/binaries/picoctf_bof
COPY --from=myrtopar/dupescan:latest /mnt/bin/dupescan_real /mnt/binaries/dupescan_real
COPY --from=myrtopar/dupescan:latest /mnt/bin/dupescan /mnt/binaries/dupescan
COPY --from=myrtopar/may:latest /mnt/bin/may_real /mnt/binaries/may_real
COPY --from=myrtopar/may:latest /mnt/bin/may /mnt/binaries/may

RUN chmod +x /mnt/binaries/*

RUN mkdir -p /crash_inputs

#copying crash inputs
COPY --from=myrtopar/june:latest /crash_inputs/june_input /crash_inputs/june_input
COPY --from=myrtopar/june:latest /crash_inputs/june_alt_input /crash_inputs/junealt_input
COPY --from=myrtopar/july:latest /crash_inputs/july_input /crash_inputs/july_input
COPY --from=myrtopar/vuln:latest /crash_inputs/vuln_input /crash_inputs/vuln_input
COPY --from=myrtopar/aspell:latest /crash_inputs/aspell_input /crash_inputs/aspell_input
COPY --from=myrtopar/iwconfig:latest /crash_inputs/iwconfig_input /crash_inputs/iwconfig_input
COPY --from=myrtopar/ncompress:latest /crash_inputs/ncompress_input /crash_inputs/ncompress_input
COPY --from=myrtopar/stacksix:latest /crash_inputs/stacksix_input /crash_inputs/stacksix_input
COPY --from=myrtopar/picoctf_bof:latest /crash_inputs/picoctf_input /crash_inputs/picoctf_bof_input
COPY --from=myrtopar/dupescan:latest /crash_inputs/dupescan_input /crash_inputs/dupescan_input
COPY --from=myrtopar/may:latest /crash_inputs/may_input /crash_inputs/may_input

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]

#june done
#junealt done
#july done
#vuln done
#iwconfig done
#ncompress done
#aspell done
#stacksix done
#picoctf done
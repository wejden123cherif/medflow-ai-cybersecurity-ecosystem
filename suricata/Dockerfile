FROM ubuntu:22.04

LABEL maintainer="MedFlow AI Security Team"
LABEL description="Suricata IDS for MedFlow AI Cybersecurity Ecosystem"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        software-properties-common \
        curl \
        ca-certificates \
        iproute2 \
        libpcap-dev \
        python3 \
        python3-pip \
    && add-apt-repository -y universe \
    && apt-get update \
    && apt-get install -y --no-install-recommends suricata \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN suricata-update --no-merge 2>/dev/null || true

RUN mkdir -p /var/log/suricata /etc/suricata/rules

COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/local.rules /etc/suricata/rules/local.rules

VOLUME ["/var/log/suricata"]

ENTRYPOINT ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0", "--set", "vars.address-groups.HOME_NET=any", "-l", "/var/log/suricata/"]

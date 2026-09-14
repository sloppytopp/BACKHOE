# BACKHOE — OSINT recon that gives you an answer, not a data dump.
#
# Build:  docker build -t backhoe .
# Run:    docker run --rm backhoe person-check admin@some-domain.com
#
# Note on keyed backends (Shodan/Censys): the interactive key prompt in
# keys.py needs a real tty to work inside a container — pass `-it`, e.g.
# `docker run --rm -it backhoe infra-check some-domain.com`. To persist a
# saved key across runs instead of re-prompting every time, mount a
# volume over ~/.config/backhoe: `-v backhoe-keys:/home/backhoe/.config/backhoe`.
# Passing SHODAN_API_KEY/CENSYS_API_KEY via `-e` skips the prompt entirely.

FROM python:3.12-slim AS build

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY backhoe ./backhoe
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim

# Run as a non-root user — this tool makes outbound network calls against
# targets the operator names; it has no business running as root.
RUN useradd --create-home --shell /bin/bash backhoe
COPY --from=build /install /usr/local
USER backhoe
WORKDIR /home/backhoe

ENTRYPOINT ["backhoe"]
CMD ["--help"]

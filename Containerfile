# Containerfile for rftp — a minimal, read-only anonymous FTP server.
#
# Build:  podman build -t rftp .
# Run:    podman run -d --name rftp -p 2121:21 \
#           -v /srv/ftp:/ftp:ro -v /etc/rftp:/conf:ro rftp
#
# The runtime stage is a scratch container: it contains only the rftp binary
# at /rftp (the entrypoint), a default configuration at /conf/rftp.yaml, and
# default content (README.md) in the served directory /ftp.

# ---- Stage 1: build a static binary with the openSUSE BCI Go image ---------
FROM registry.opensuse.org/opensuse/bci/golang:latest AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
# CGO_ENABLED=0 produces a static binary that runs in a scratch container.
RUN CGO_ENABLED=0 go build -trimpath -o /out/rftp ./cmd/rftp

# ---- Stage 2: scratch runtime — only the binary ------------------------------
FROM scratch
COPY --from=build /out/rftp /rftp
COPY container/rftp.yaml /conf/rftp.yaml
COPY README.md /ftp/README.md
# Run unprivileged. A scratch image has no /etc/passwd, so use a numeric
# uid/gid (65534 = nobody). Data under /ftp must be readable by this uid.
USER 65534:65534
EXPOSE 21/tcp
ENTRYPOINT ["/rftp"]
CMD ["-config", "/conf/rftp.yaml"]

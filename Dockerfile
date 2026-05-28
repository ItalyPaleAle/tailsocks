FROM gcr.io/distroless/static-debian12:nonroot
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/tailsocks /bin
# tsnet state is written to ./tsnet-state relative to WORKDIR
# mount /data as a volume to persist it
WORKDIR /data
CMD ["/bin/tailsocks"]

FROM gcr.io/distroless/static-debian12:nonroot
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/tailsocks /bin
WORKDIR /tmp
CMD ["/bin/tailsocks"]

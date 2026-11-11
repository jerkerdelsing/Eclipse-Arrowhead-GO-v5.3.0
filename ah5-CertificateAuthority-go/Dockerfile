# Standalone build context: this directory only.
ARG GO_IMAGE=golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf
FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go build -trimpath -o /out/CertificateAuthority ./cmd/certificateauthority
FROM scratch
COPY --from=build /out/CertificateAuthority /usr/local/bin/CertificateAuthority
USER 65532:65532
EXPOSE 8448
ENTRYPOINT ["/usr/local/bin/CertificateAuthority"]
CMD ["-config", "/config/config.json"]

# Standalone build context: this directory only.
ARG GO_IMAGE=golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf
FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go build -trimpath -o /out/TestTranslation ./cmd/testtranslation
FROM scratch
COPY --from=build /out/TestTranslation /usr/local/bin/TestTranslation
USER 65532:65532
EXPOSE 8552
ENTRYPOINT ["/usr/local/bin/TestTranslation"]
CMD ["-config", "/config/config.json"]

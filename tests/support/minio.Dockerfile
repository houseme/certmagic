# Test-only MinIO fixture. The upstream community image is no longer public.
# RELEASE.2025-09-07T16-13-09Z, fixed to its peeled commit (not a mutable tag).
FROM golang:1.24.6-bookworm AS build
WORKDIR /src
RUN git init . \
    && git remote add origin https://github.com/minio/minio.git \
    && git fetch --depth=1 origin 07c3a429bfed433e49018cb0f78a52145d4bedeb \
    && git checkout --detach FETCH_HEAD
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -o /minio .

FROM debian:bookworm-slim
COPY --from=build /minio /usr/local/bin/minio
COPY --from=build /src/LICENSE /licenses/minio/LICENSE
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV MINIO_BROWSER=off MINIO_UPDATE=off
ENTRYPOINT ["/usr/local/bin/minio"]

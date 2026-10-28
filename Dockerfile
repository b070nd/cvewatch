# syntax=docker/dockerfile:1
FROM golang:1.27 AS build
WORKDIR /src
COPY app/go.mod app/go.sum ./
RUN go mod download
COPY app/ ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvewatch ./src/cmd/cvewatch
RUN mkdir /out/data /out/alerts

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cvewatch /cvewatch
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/alerts /alerts
COPY app/config/config.yaml /app/config/
# Techs and feeds are built into the binary. Project configs are mounted at
# /app/config/projects, never baked in.
VOLUME ["/data", "/alerts"]
USER 65532:65532
ENTRYPOINT ["/cvewatch", "-root", "/app"]
CMD ["daemon"]

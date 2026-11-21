# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=1.1.1
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/symforge ./cmd/symforge

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/symforge /usr/local/bin/symforge
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/symforge"]
CMD ["--help"]

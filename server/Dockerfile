FROM golang:1.27.4-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/agent ./cmd/agent
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-w -s" -o /dist/rmm-agent-linux-amd64 ./cmd/agent && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-w -s" -o /dist/rmm-agent-linux-arm64 ./cmd/agent && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-w -s -H windowsgui" -o /dist/rmm-agent-windows-amd64.exe ./cmd/agent && \
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-w -s" -o /dist/rmm-agent-darwin-amd64 ./cmd/agent && \
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-w -s" -o /dist/rmm-agent-darwin-arm64 ./cmd/agent
COPY cmd/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o /rmm-server ./cmd/server
FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /rmm-server /app/rmm-server
COPY --from=builder /dist /app/public/downloads
COPY static /app/static
EXPOSE 8080
VOLUME ["/app/data"]
CMD ["/app/rmm-server"]

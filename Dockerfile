FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/aegis-server ./cmd/aegis-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/aegis-server /aegis-server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/aegis-server"]

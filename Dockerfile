FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /k8s-security-linter ./cmd/k8s-security-linter

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /k8s-security-linter /usr/local/bin/k8s-security-linter
ENTRYPOINT ["/usr/local/bin/k8s-security-linter"]
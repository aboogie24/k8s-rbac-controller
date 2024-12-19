FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o controller

FROM alpine:3.18
WORKDIR /
COPY --from=builder /app/controller .
ENTRYPOINT ["/controller"]
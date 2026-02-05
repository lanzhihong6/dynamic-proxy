# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install wget to download ip2region database
RUN apk add --no-cache wget

COPY go.mod go.sum ./
RUN go mod download

# Download the latest ip2region database
RUN wget https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region.xdb -O ip2region.xdb

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dynamic-proxy .

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/dynamic-proxy .
COPY --from=builder /app/ip2region.xdb .
COPY config.yaml .

EXPOSE 17283 17284 17285 17286
CMD ["./dynamic-proxy"]

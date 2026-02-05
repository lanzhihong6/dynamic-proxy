# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates wget

COPY go.mod ./
RUN go mod download
RUN go get github.com/lionsoul2014/ip2region/binding/golang@master
RUN go mod tidy

# 同时下载 V4 和 V6 数据库
RUN wget https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb -O ip2region_v4.xdb
RUN wget https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v6.xdb -O ip2region_v6.xdb

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dynamic-proxy .

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/dynamic-proxy .
COPY --from=builder /app/ip2region_v4.xdb .
COPY --from=builder /app/ip2region_v6.xdb .
COPY config.yaml .

EXPOSE 17283 17284 17285 17286
CMD ["./dynamic-proxy"]

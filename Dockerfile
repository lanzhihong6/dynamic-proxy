# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates wget

COPY go.mod ./
RUN go get github.com/lionsoul2014/ip2region/binding/golang@master
RUN go mod tidy

# 使用官方 raw 域名，确保 100% 成功下载
RUN wget https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb -O ip2region_v4.xdb
RUN wget https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb -O ip2region_v6.xdb

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -v -o dynamic-proxy .

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

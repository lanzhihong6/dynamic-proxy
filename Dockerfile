# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates wget

COPY go.mod ./
# 先下载基础依赖
RUN go mod download
# 显式获取 ip2region 的最新 master 版本，不带那个该死的哈希
RUN go get github.com/lionsoul2014/ip2region/binding/golang@master
# 整理依赖
RUN go mod tidy

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

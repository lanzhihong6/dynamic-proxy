# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates wget

# 1. 先准备依赖
COPY go.mod ./
# 使用 go get 强制同步正确的依赖
RUN go mod download || true
RUN go get github.com/lionsoul2014/ip2region/binding/golang@v0.0.0-20240510063043-307a34203b9c
RUN go get golang.org/x/net/proxy
RUN go get gopkg.in/yaml.v3
RUN go mod tidy

# 2. 下载数据库
RUN wget https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb -O ip2region_v4.xdb
RUN wget https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v6.xdb -O ip2region_v6.xdb

# 3. 复制代码并构建
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

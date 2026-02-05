# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates wget

# 1. 复制基础文件
COPY go.mod ./
COPY main.go ./

# 2. 只有代码在位时，tidy 才能自动识别出代码里用到的包
RUN go mod tidy

# 3. 下载数据库
RUN wget https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb -O ip2region_v4.xdb
RUN wget https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb -O ip2region_v6.xdb

# 4. 构建
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

# 1. 构建阶段
FROM golang:1.22-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0
ENV GOOS=linux

COPY go.mod ./
# COPY go.sum ./
RUN go mod download

COPY *.go ./
# 编译时去除调试信息，减小体积
RUN go build -ldflags="-s -w" -o server main.go

# 2. 运行阶段
FROM alpine:latest

# 安装基础库、时区、以及 curl (用于容器内自测)
RUN apk --no-cache add tzdata ca-certificates curl
ENV TZ=Asia/Shanghai

WORKDIR /app

# 复制二进制文件
COPY --from=builder /app/server .

# 🔥 不要设置 ENV PORT，让代码自己读取系统注入的
# EXPOSE 只是声明，不是强制
EXPOSE 8080

# 启动命令
CMD ["./server"]

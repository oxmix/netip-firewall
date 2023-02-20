FROM alpine:3.17

RUN apk --no-cache add php php-json php-curl php-pcntl php-openssl nftables

WORKDIR /app
COPY ./tasks.php .

CMD ["/app/tasks.php"]

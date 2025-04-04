FROM alpine:latest

RUN apt update # should fail, apt is not present in alpine

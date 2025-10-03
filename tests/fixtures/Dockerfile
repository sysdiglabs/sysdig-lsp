FROM alpine AS builder

RUN apk update

RUN apk add curl

RUN curl -L https://get.jenkins.io/war-stable/2.401.3/jenkins.war -o /jenkins.war

FROM nginx:latest


RUN apt update && apt full-upgrade -y

COPY --from=builder /jenkins.war /jenkins.war

ENV foo=bar

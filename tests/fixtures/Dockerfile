FROM alpine AS builder

RUN apk update

RUN apk add curl

RUN curl -L https://ftp.belnet.be/mirror/jenkins/war/2.455/jenkins.war -o /jenkins.war

FROM nginx:latest

RUN apt update && apt full-upgrade -y

COPY --from=builder /jenkins.war /jenkins.war

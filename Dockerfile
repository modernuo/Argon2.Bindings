FROM ubuntu:16.04 as ubuntu-16
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM ubuntu:18.04 as ubuntu-18
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM ubuntu:20.04 as ubuntu-20
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM debian:9 as debian-9
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM debian:10 as debian-10
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM centos:7 as centos-7
RUN yum update -y && yum install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM centos:8 as centos-8
RUN yum update -y && yum install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM fedora:32 as fedora-32
RUN dnf upgrade -y && dnf install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM fedora:33 as fedora-33
RUN dnf upgrade -y && dnf install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
ENV OPTTARGET x86-64
RUN make

FROM alpine:latest
RUN mkdir -p ./runtimes/ubuntu.16.04-x64/native
RUN mkdir -p ./runtimes/ubuntu.18.04-x64/native
RUN mkdir -p ./runtimes/ubuntu.20.04-x64/native

RUN mkdir -p ./runtimes/debian.9-x64/native
RUN mkdir -p ./runtimes/debian.10-x64/native

RUN mkdir -p ./runtimes/centos.7-x64/native
RUN mkdir -p ./runtimes/centos.8-x64/native

RUN mkdir -p ./runtimes/fedora.32-x64/native
RUN mkdir -p ./runtimes/fedora.33-x64/native

COPY --from=ubuntu-16 /argon2/libargon2.so.1 ./runtimes/ubuntu.16.04-x64/native/libargon2.so
COPY --from=ubuntu-18 /argon2/libargon2.so.1 ./runtimes/ubuntu.18.04-x64/native/libargon2.so
COPY --from=ubuntu-20 /argon2/libargon2.so.1 ./runtimes/ubuntu.20.04-x64/native/libargon2.so

COPY --from=debian-9 /argon2/libargon2.so.1 ./runtimes/debian.9-x64/native/libargon2.so
COPY --from=debian-10 /argon2/libargon2.so.1 ./runtimes/debian.10-x64/native/libargon2.so

COPY --from=centos-7 /argon2/libargon2.so.1 ./runtimes/centos.7-x64/native/libargon2.so
COPY --from=centos-8 /argon2/libargon2.so.1 ./runtimes/centos.8-x64/native/libargon2.so

COPY --from=fedora-32 /argon2/libargon2.so.1 ./runtimes/fedora.32-x64/native/libargon2.so
COPY --from=fedora-33 /argon2/libargon2.so.1 ./runtimes/fedora.33-x64/native/libargon2.so

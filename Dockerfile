FROM ubuntu:xenial as ubuntu-xenial
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
RUN make

FROM ubuntu:bionic as ubuntu-bionic
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
RUN make

FROM ubuntu:focal as ubuntu-focal
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
RUN make

FROM debian:stretch as debian-stretch
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
RUN make

FROM debian:buster as debian-buster
RUN apt-get update && apt-get install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
RUN make

FROM centos:7 as centos-7
RUN yum update -y && yum install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
RUN make

FROM centos:8 as centos-8
RUN yum update -y && yum install -y gcc make
COPY ./argon2-src ./argon2
WORKDIR /argon2
RUN make

FROM alpine:latest
RUN mkdir -p ./runtimes/ubuntu.16-x64/native
RUN mkdir -p ./runtimes/ubuntu.18-x64/native
RUN mkdir -p ./runtimes/ubuntu.20-x64/native

RUN mkdir -p ./runtimes/debian.9-x64/native
RUN mkdir -p ./runtimes/debian.10-x64/native

RUN mkdir -p ./runtimes/centos.7-x64/native
RUN mkdir -p ./runtimes/centos.8-x64/native

COPY --from=ubuntu-xenial /argon2/libargon2.so.1 ./runtimes/ubuntu.16-x64/native/libargon2.so
COPY --from=ubuntu-bionic /argon2/libargon2.so.1 ./runtimes/ubuntu.18-x64/native/libargon2.so
COPY --from=ubuntu-focal /argon2/libargon2.so.1 ./runtimes/ubuntu.20-x64/native/libargon2.so

COPY --from=debian-stretch /argon2/libargon2.so.1 ./runtimes/debian.9-x64/native/libargon2.so
COPY --from=debian-buster /argon2/libargon2.so.1 ./runtimes/debian.10-x64/native/libargon2.so

COPY --from=centos-7 /argon2/libargon2.so.1 ./runtimes/centos.7-x64/native/libargon2.so
COPY --from=centos-8 /argon2/libargon2.so.1 ./runtimes/centos.8-x64/native/libargon2.so
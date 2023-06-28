FROM ubuntu:16.04

LABEL arielinfo="github.com/dimmarvel"

RUN apt-get update
RUN apt-get install -y \
    build-essential \
    libqrencode-dev \
    libtool \
    autotools-dev \
    automake \
    pkg-config \ 
    libssl-dev \
    libevent-dev \ 
    bsdmainutils \
    git \
    cmake \ 
    libboost-all-dev \
    libgmp3-dev \
    software-properties-common \
    libtool \
    libssl-dev \
    libevent-dev

RUN add-apt-repository ppa:bitcoin/bitcoin
RUN apt-get update

RUN apt-get install -y \
    libdb4.8-dev \
    libdb4.8++-dev \
    wget \
    curl \
    libqt5gui5 \
    libqt5core5a \
    libqt5dbus5 \
    qttools5-dev \
    qttools5-dev-tools \
    libprotobuf-dev \
    protobuf-compiler \
    qrencode

RUN mkdir -p /usr/src/ariel
WORKDIR /usr/src/ariel

COPY . /usr/src/ariel

#Was copy from ./contrib/script/setup-ubuntu16.sh
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get update
RUN apt-get install autoconf automake binutils bison bsdmainutils ca-certificates curl faketime g++-8 gcc-8 git libtool patch pkg-config python3 python3-pip cmake libcurl4-openssl-dev libgmp-dev libmicrohttpd-dev libminiupnpc-dev -y
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 80 --slave /usr/bin/g++ g++ /usr/bin/g++-8 --slave /usr/bin/gcov gcov /usr/bin/gcov-8
#------------------------------------------------

WORKDIR /usr/src/ariel

RUN ./contrib/install_db4.sh `pwd`

RUN ./autogen.sh
#RUN ./configure --without-gui
#RUN make -j12
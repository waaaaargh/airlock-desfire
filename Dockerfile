FROM fedora:latest

RUN dnf install -y git make automake gcc gcc-c++ git libtool help2man pcsc-lite pcsc-lite-devel openssl-devel libcurl-devel

WORKDIR /app

RUN git clone https://github.com/nfc-tools/libnfc.git
RUN git clone https://github.com/nfc-tools/libfreefare.git
RUN git clone https://github.com/frankmorgner/vsmartcard.git

WORKDIR /app/libnfc
RUN autoreconf -vis
RUN ./configure --with-drivers=pcsc --prefix=/usr --sysconfdir=/etc
RUN make
RUN make install

WORKDIR /app/libfreefare
RUN autoreconf -vis
RUN ./configure --prefix=/usr
RUN make
RUN make install

WORKDIR /app/vsmartcard
RUN git submodule update --init --recursive
WORKDIR /app/vsmartcard/virtualsmartcard
RUN autoreconf --verbose --install
RUN ./configure --sysconfdir=/etc
RUN make
RUN make install

WORKDIR /app/airlock
ADD . .
RUN mkdir build
RUN make

CMD [ "pcscd", "-fi", "--disable-polkit" ]
Overview
========

Phoenix is an extension of the [Graphene](https://github.com/oscarlab/graphene)
libOS for Intel SGX hardware enclaves.  Phoenix adds to Graphene: 

- an encrypted and integrity-protected filesystem
- shared memory
- the ability to proxy time-related system calls to a time server

Phoenix also includes an OpenSSL engine that proxies RSA-2048 key operations to
an enclaved key server.

Phoenix implements all extensions as servers.  For instance, the encrypted filesystem is a
userspace server that runs on top of the Phoenix libOS in an enclave; a user
can configure other instances of Phoenix (such as those running applications)
to use the remote filesystem.

The Phoenix design is thus evocative of a micro-kernel, and we refer to the servers
as "kernel servers".


<a name="setup"/> Setup
=======================

We perform our tests on the Intel NUC Skull Canyon NUC6i7KYK Kit with 6th
generation Intel Core i7-6770HQ Processor (2.6 GHz), with 32 GiB of RAM.  The
processor consists of four hyperthreaded cores, and has a 6 MiB cache.

For our operating system, we use
[`lubuntu-16.04.1-desktop-amd64.iso`](http://cdimage.ubuntu.com/lubuntu/releases/16.04.1/release),
with the following kernels:

- `4.10.0-38-generic #42~16.04.1-Ubuntu SMP Tue Oct 10 16:32:20 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux`
- `4.4.0-157-generic #185-Ubuntu SMP Tue July 23 09:17:01 UTC 2019`

At the time of developing Phoenix, Graphene only suppported Ubuntu 16.04.

In this guide, we assume all source is downloaded to `~/src` and all artifacts
installed under `$HOME`.


SGX SDK and Driver
------------------

Download and install the Intel SGX Driver:

```
mkdir ~/src
cd ~/src
wget https://github.com/intel/linux-sgx-driver/archive/sgx_driver_1.9.tar.gz
tar zxvf sgx_driver_1.9.tar.gz
rm sgx_driver_1.9.tra.gz
cd linux-sgx-driver-sgx_driver_1.9
make
```

Download and install the Intel SGX SDK:

```
cd ~/src
wget https://github.com/intel/linux-sgx/archive/sgx_2.6.tar.gz
tar zxvf sgx_2.6.tar.gz
cd linux-sgx-sgx_2.6
sudo apt-get install build-essential ocaml automake autoconf \
         libtool wget python libssl-dev libcurl14-openssl-dev \
         protobuf-compiler libprotobuf-dev debhelper cmake \
         python

./download_prebuilt.sh
make                    # builds the SDK and PSW
make sdk_install_pkg    # builds the SDK installer
make deb_pkg            # builds the PWS installer

cd linux/installer/bin

# install the SDK to /opt
sudo ./sgx_linux_x64_sdk_2.6.100.51363.bin

#install the PSW
cd ~/src/linux-sgx-sgx_2.6/linux/installer/deb
sudo dpkg -i ./libsgx-urts_2.6.100.51363-xenial1_amd64.deb \
    ./libsgx-enclave-common_2.6.100.51363-xenial1_amd64.deb
```

Phoenix needs the PSW, but not the SDK.  That said, if using the SDK for other
purposes, first set a few environment variables:

```
source /opt/sgxsdk/environment
```

<a name="building"/> Building
=============================

Phoenix libOS
-------------

First, install the dependencies:

```
sudo apt-get install -y build-essential autconf gawk bison \
         python-protobuf libprotobuf-c-dev \
         protobuf-c-compiler
```

Download Pheonix and update the driver submodule (Graphene slightly
modifies Intel's default driver):

```
cd ~/src
git clone https://github.com/smherwig/phoenix
cd phoenix
git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver
```

Generate an enclave signing key

```
cd Pal/src/host/Linux-SGX/signer
openssl genrsa -3 -out enclave-key.pem 3072
mkdir -p ~/share/phoenix
cp enclave-key.pem ~/share/phoenix
```

Phoenix uses a slightly modified version of [BearSSL](https://bearssl.org);
first build this component, as it is not yet integrated into Graphene's
Makefile system:

```
cd ~/src/phoenix/bearssl-0.6
make
```

Next, build Phoenix:

```
cd ~/src/phoenix
make SGX=1
```

When prompted for the Intel SGX driver and version, enter (changing the home
directory, as appropriate):

```
Enter the Intel SGX driver directory: /home/smherwig/src/linux-sgx-driver-sgx_driver_1.9

Enter the driver version (default: 1.9): 1.9
```

The script `Tools/make_phoenix_keys.sh` may be used to generate a root
certificate (`root.crt`) and a leaf certificate (`proc.crt`) and key
(`proc.key`).  The kernel servers and Phoenix application instances use this
keying material.  For convenience, a copy of the keying material is present in
this directory.  Copy the keying material to `~/share/phoenix`:

```
cd ~/src/phoenix/Tools
cp root.crt proc.crt proc.key ~/share/phoenix/
```


Base components
---------------

The kernel servers depend on the following libraries: the links below go to
each library's instructions for building and installing:


- [librho](https://github.com/smherwig/librho#building)
- [librpc](https://github.com/smherwig/phoenix-librpc#building)
- [lwext4](https://github.com/smherwig/lwext4#phoenix-compile)
- [libbd](https://github.com/smherwig/phoenix-libbd#building)


Kernel servers
--------------

Instructions for building the kernel servers are at the following links:

- [fileserver](https://github.com/smherwig/phoenix-fileserver#building)
- [memserver](https://github.com/smherwig/phoenix-memserver#building)
- [keyserver](https://github.com/smherwig/phoenix-keyserver#building)
- [timeserver](https://github.com/smherwig/phoenix-timeserver#building)


Additional Tools
----------------

The `makemanifest` tool is used to create a manifest for running an executable
on Phoenix:

- [makemanifest](https://github.com/smherwig/phoenix-makemanifest#building)


`spf` (SGX Page fault) is a performance tool that measures SGX paging events:

- [spf](https://github.com/smherwig/phoenix-spf#building)


<a name="post-build"/> Post-build
=================================

After building, set the `vm.mmap_in_addr` sysctl and load graphene's Linux kernel
module: `graphene_sgx`.

```
sudo sysctl vm.mmap_min_addr=0
cd ~/src/phoenix/Pal/src/host/Linux-SGX/sgx-driver
./load.sh
```

<a name="macro-benchmarks"/> Macro-benchmarks
=============================================

Instructions for running NGINX macro-benchmarks:

- [nginx-eval](https://github.com/smherwig/phoenix-nginx-eval)


<a name="micro-benchmarks"/> Micro-benchmarks
=============================================

Instrutions for running RPC micro-benchmarks:

- [librpc](https://github.com/smherwig/phoenix-librpc#micro-benchmarks)

and the kernel server micro-benchmarks:

- [fileserver](https://github.com/smherwig/phoenix-fileserver#micro-benchmarks)
- [memserver](https://github.com/smherwig/phoenix-memserver#micro-benchmarks)
- [keyserver](https://github.com/smherwig/phoenix-keyserver#micro-benchmarks)
- [timeserver](https://github.com/smherwig/phoenix-timeserver#micro-benchmarks)

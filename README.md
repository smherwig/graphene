Overview
========


<a name="setup"/> Setup
=======================

We perform our tests on the Intel NUC Skull Canyon NUC6i7KYK Kit with 6th
generation Intel Core i7-6770HQ Processor (2.6 GHz), with 32 GiB of RAM.  The
processor consists of four hyperthreaded cores, and has a 6 MiB cache.

For our operating system, we use `lubuntu-16.04.1-desktop-amd64.iso`, with
the following kernels:

- `4.10.0-38-generic #42~16.04.1-Ubuntu SMP Tue Oct 10 16:32:20 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux`
- `4.4.0-157-generic #185-Ubuntu SMP Tue July 23 09:17:01 UTC 2019.


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
suod ./sgx_linux_x64_sdk_2.6.100.51363.bin

#install the PSW
cd ~/src/linux-sgx-sgx_2.6/linux/install/deb
```

Phoenix does not use the SDK, but if you ever want to:

```
source /opt/sgxsdk/environment
```


<a name="building"/> Building
=============================

Phoenix libOS
-------------

```
sudo apt-get install -y build-essential autconf gawk bison \
         python-protobuf libprotobuf-c-dev \
         protobuf-c-compiler
```

```
cd ~/src
git clone https://github.com/smherwig/phoenix
cd phoenix
git submodul update --init -- Pal/src/host/Linux-SGX/sgx-driver
cd Pal/src/host/Linux-SGX/signer
openssl genrsa -3 -out enclave-key.pem 3072
cd ~/src/phoenix/bearssl-0.6
make
cd ~/src/phoenix
make SGX=1
```

Base components
---------------

- [librho](https://github.com/smherwig/librho#building)
- [librpc](https://github.com/smherwig/librpc#building)
- [lwext4](https://github.com/smherwig/#lwext4building)
- [libbd](https://github.com/smherwig/libbd#building)


Kernel servers
--------------

- [fileserver](https://github.com/smherwig/phoenix-fileserver#building)
- [memserver](https://github.com/smherwig/phoenix-memserver#building)
- [keyserver](https://github.com/smherwig/phoenix-keyserver#building)
- [timeserver](https://github.com/smherwig/phoenix-timeserver#building)


Additional Tools
----------------

- [makemanifest](https://github.com/smherwig/phoenix-makemanifest#building)
- [spf](https://github.com/smherwig/phoenix-spf#building)


<a name="post-build"/> Post-build
=================================

```
sudo sysctl vm.mmap_min_addr=0
cd ~/src/phoenix/Pal/src/host/Linux-SGX/sgx-driver
./load.sh
```

<a name="macro-benchmarks"/> Macro-benchmarks
=============================================

NGINX:

- [nginx-eval](https://github.com/smherwig/phoenix-nginx-eval)


<a name="micro-benchmarks"/> Micro-benchmarks
=============================================

RPC micro-benchmark:

- [librpc](https://github.com/smherwig/phoenix-librpc#micro-benchmarks)

Kernel server micro-benchmarks:

- [fileserver](https://github.com/smherwig/phoenix-fileserver#micro-benchmarks)
- [memserver](https://github.com/smherwig/phoenix-memserver#micro-benchmarks)
- [keyserver](https://github.com/smherwig/phoenix-keyserver#micro-benchmarks)
- [timeserver](https://github.com/smherwig/phoenix-timeserver#micro-benchmarks)



Limitations
===========

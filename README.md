This repo contains 3 parts:

* Testbed programs that can be deployed in P4 switche
* MiniNet programs that simulate OmniMon
* Collective analysis that works for both testbed and MiniNet programs

# Part I: Testbed Programs

## Install Dependencies：

We require the following depedencies to run Omnimon testbed programs.

* **cmake** >= 3.12
* **autoreconf:** `sudo apt-get install autoconf -y`
* **libpcap:**  `sudo apt-get install libpcap-dev -y`
* **libnuma:** `sudo apt-get install libnuma-dev -y`
* **libgmp:** `sudo apt-get install libgmp-dev -y`

* **iniparser**:

```
git clone http://github.com/ndevilla/iniparser.git
cd iniparser
make
sudo cp lib* /usr/lib/
sudo cp src/*.h /usr/include
```
* **mtcp**:

```
git clone https://github.com/mtcp-stack/mtcp.git
cd mtcp
git submodule init
git submodule update
sudo ifconfig eth0 down  # Suppose one dpdk NIC is eth0
sudo ifconfig eth1 down  # Suppose another one dpdk NIC is eth1
./setup_mtcp_dpdk_env.sh [<path to $RTE_SDK>] 
    - Press [15] to compile x86_64-native-linuxapp-gcc version
    - Press [18] to install igb_uio driver for Intel NICs
    - Press [22] to setup 2048 2MB hugepages
    - Press [24] to register the Ethernet ports
    - Press [35] to quit the tool
sudo ifconfig dpdk0 10.0.0.31/24 up   # Assign ip to the mtcp dpdk0, it is recommended to use 10.0.0.0/24 network segments
sudo ifconfig dpdk1 10.0.1.31/24 up   # Assign ip to the mtcp dpdk1, it is recommended to use 10.0.1.0/24 network segments

export RTE_SDK=`echo $PWD`/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc
autoreconf -ivf
./configure --with-dpdk-lib=$RTE_SDK/$RTE_TARGET
make -j 4
```


## Hardware and Topology

Our testbed requires three servers and two switches, connected as shown in the figure below.

![](./img/topo.png)

* Server: 

  * One server acts as the Omnimon Controller, which requires one NIC that supports DPDK driver. ([Here](http://core.dpdk.org/supported/) lists the devices that can work with DPDK drivers)
  * The other two servers are used as sender and receiver, both of which requires two NICs that supports DPDK driver or one dual-port NIC.

* Switch:

  * One switch is used to deploy the Omnimon dataplane program, which needs to support P4.

  * Another one switch is used for Controller to connect the hosts in the network independently.

    

## Configure and Compile

Omnimon contains the following configuration files and you need to modify these files to compile and run the Omnimon testbed program. (all the files are in the testbed directory)

1. **CMakeLists.txt**    (used to generate Makefile)

   You need to modify the `MTCP_DIR` variable in the CMakeLists.txt according to your environment.

2. **config.ini**    (the configuration file of Omnimon)

   The complete configuration parameters of Omnimon are shown in the table below. The option marked with * means that you have to set according to the operating environment.

   | Field             | Meaning                                                      |
   | ----------------- | ------------------------------------------------------------ |
   | **[Common]**      |                                                              |
   | * trace_dir       | directory of the test trace                                  |
   | * trace_pcap_list | file listing all raw pcap files                              |
   | key_len           | flow key length in bit (default 5-tuple)                     |
   | interval_len      | epoch length (default 100ms)                                 |
   | [Host]            |                                                              |
   | host_max_key      | max flows of each epoch in the test trace                    |
   | max_events        | mtcp events queue length                                     |
   | process_cpu       | the logical core id to run the mtcp thread (default 0)       |
   | * mtcp_conf_file  | the absolute path of mtcp configuration file necessary for mtcp stack |
   | **[Controller]**  |                                                              |
   | * ip_addr         | the ip address you assigned to dpdk0 of Controller when installing mtcp |
   | listen_port       | the listening port of Controller                             |
   | max_events        | mtcp events queue length                                     |
   | process_cpu       | the logical core id to run the mtcp thread (default 0)       |
   | * mtcp_conf_file  | the absolute path of mtcp configuration file necessary for mtcp stack |

3. **mtcp_om_[host/controller].conf**   （the configuration file of mtcp stack)

   We provide different configuration files for Omnimon's controller and host. You only need to set the specific path of the `mtcp_conf_file` option in **config.ini** and do not need to modify the file content.

4. **config/arp.conf**     (required by mtcp stack)

   * You need to update all mac address of dpdk0 of each server after installing the mtcp stack.

   * Mtcp thread will read the arp.conf automatically, do not change the file path.

5. **config/route.conf**      (required by mtcp stack)

  * The route rules for mtcp stack. If you use the recommended network segment, 
    you can directly use the file without modification.
  * Mtcp thread will read the route.conf automatically, do not change the file path.



After modifying the above configuration files, you can compile the executable files using following commands on each server.

```
cd ${omnimon_dir}/testbed
cmake .
make controller
make host_rx
make host_tx
```



## Setup Tofino

We provide a simple version of Omnimon data plane P4 program. The function of this program mainly includes parsing the header of Omnimon and completing the basic forwarding function. We hide the counting part which requires the Stateful ALU of Tofino according to the Barefoot NDA. 

When the program is deployed, you need to configure the port and add the flow entry.

## Run Controller

Make sure the current directory is `${omnimon_dir}/testbed`, run

```
sudo ./bin/controller config.ini
```

## Run End-Hosts

On sender node, run：

```
sudo ./bin/host_tx config.ini 1
```

On receiver node, run:

```
sudo ./bin/host_rx config.ini 2
```


## Result Screenshots

TBD

# Part II: MiniNet Programs

We provide an Omnimon prototype based on Mininet and p4-behavioral model.

## Install Dependencies

We require the following depedencies to run Omnimon mininet programs.

* **cmake** >= 3.12
* **libpcap:**  `sudo apt-get install libpcap-dev -y`
* **libzmq:** `sudo apt-get install libzmq3-dev`

* **iniparser**:

```
git clone http://github.com/ndevilla/iniparser.git
cd iniparser
make
sudo cp lib* /usr/lib/
sudo cp src/*.h /usr/include
```

For the mininet and bmv2 environmen, you can follow the instructions on the official site and install the dependencies easily.

【emmmm，锦博的文档，这部分没有详细的，我把锦博的dpdk相关的依赖删了】

```
bvm2    : https://github.com/p4lang/behavioral-model#dependencies
p4c     : https://github.com/p4lang/p4c#getting-started
Mininet : http://mininet.org/download/
```



## Mininet Topology

There are four hosts (h1, h2, h3, h4), three p4 switches (s1, s2, s3) and a controller in the network. The prototype consists of three parts, which run on the host, switch and controller respectively.

![](./img/mininet.png)



## Configure and Compile

You need to modify the following configurattion files to compile and run the Omnimon mininet program.

1. `mininet/bmv2/env.sh`

You should change the value of `BMV2_PATH` to the correct path of bmv2 folder

2. `mininet/config.ini` 

The complete configuration parameters of mininet verison Omnimon are shown in the table below. The option marked with * means that you have to set according to the operating environment.

| Field             | Meaning                                  |
| ----------------- | ---------------------------------------- |
| **[Common]**      |                                          |
| * trace_dir       | directory of the test trace              |
| * trace_pcap_list | file listing all raw pcap files          |
| key_len           | flow key length in bit (default 5-tuple) |
| interval_len      | epoch length (default 100ms)             |

After modifying the configuration file, you can compile the executable files using following commands on each server.

```
cd mininet/end_host
mkdir build
cd build
cmake ..
make end_host 
make controller
```



## Start Mininet

*  Terminal-1 run the following command to start the simulated topologic and compile and run the P4 code of OmniMon: 

```bash
cd ${omnimon_dir}/mininet/bmv2
./run_bmv2.sh
```

* Terminal-2 run the following command to add flow_table for P4 switches in Mininet:

```bash
cd ${omnimon_dir}/mininet/bmv2
./set_switches.sh
```



## Run Controller

Terminal-1 Run:

```
h5 ../end_host/controller ../end_host/config.ini &
```



## Run End-Hosts

Terminal-1 Run:

```
h1 ../end_host/end_host ../end_host/config.ini 1 &
h2 ../end_host/end_host ../end_host/config.ini 2 &
h3 ../end_host/end_host ../end_host/config.ini 3 &
h4 ../end_host/end_host ../end_host/config.ini 4 &
```



## Result Screenshots

When the program ends, end_host output will be directly written in `./result/outpufilename##`. You need to run the following command to get the switch output.

```
cd ${omnimon_dir}/mininet/bmv2 
python read_register.py
```

The switch output will also be written in  `./result/outpufilename##`

# Part III: Collective Analysis

This repo implements the collective analysis of OmniMon individually.
The analysis programe works for results generated by either testbed program or Mininet program.

## Dependencies

Install eigen library: [http://eigen.tuxfamily.org/index.php]

## Prepare input files

Each epoch has a directory of input files for the analysis. These files are generated by switches and end-hosts.

The files include:

- device\_ids.txt: specify the ids of all end-hosts and switches
- path.txt: specify the expected path along which each flow travels
- src\_X: output file of each source end-host whose id is X. This file containing all flows sent from end-host X.
- dst\_X\_Y: output file of each destination end-host. This file includes flow values that are sent from end-host X and received by end-host Y.
- sX.txt: output of switch X.

We provide a simple sample in directory [collective\_analysis/sample].

## Compile and Run

1. Enter collective analysis directory:
```
cd collective_analysis
```

2. Compile
```
make
```

3. Run
```
./main [dir]
```
Here, dir is the input directory.

## Example

In our sample example, some packets of a flow are dropped by Switch 3. The result is:

TBD.

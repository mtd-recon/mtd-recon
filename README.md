# MTD against reconnaissance

## Description
This is an MTD project written to accompany our bachelor's thesis. It contains two main components IP-Shuffling and Port-Shuffling. The controller switches real IPs to virtual IPs and vice versa. The same principle applies for the ports. All traffic addressed to real IPs/ports is dropped. This way, clients are forced to address the servers by the shuffled virtual addresses/ports.

## Prerequisites
* Ubuntu 16.04 LTS (or later)
* Pyton 3.9 (Ryu is not compatible with 3.10)
* Mininet 2.3.0
* Ryu 

## Installation
```Clone the repo
git clone https://github.com/mtd-recon/mtd-recon.git
```

## Usage
```
sudo python3 network.py
```
```
ryu-manager ryu_controller.py
```

## Credits
* [Pascal Kunz](https://github.com/afk-proficoder)
* [Nicholas Mayone](https://github.com/nmayone)
* [Gürkan Gür](https://github.com/gurgurka)
* [Wissem Soussi](https://github.com/wsoussi)



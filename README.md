# MTD against reconnaissance

## Description
This is an MTD project written to accompany our bachelor's thesis. It contains two main components IP-Shuffling and Port-Shuffling. The controller switches real IPs to virtual IPs and vice versa. The same principle applies for the ports. All traffic addressed to real IPs/ports is dropped. This way, clients are forced to address the servers by the shuffled virtual addresses/ports.

## Prerequisites
- Ubuntu 22.04.2 LTS (Jammy Jellyfish)
- Python 3.9
- Mininet 2.3.0
- Ryu 4.34

## Installation

```
sudo apt update
sudo apt install mininet -y
```

### optional (needs GUI):
```
sudo apt install xterm -y
```

### `eventlet` is not compatible with python 3.10. It is required to add 3.9 python in addition to the VM and to downgrade `eventlet` and `gunicorn`:
```
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3-pip python3.9 python3.9-distutils -y
sudo python3.9 -m pip install gunicorn==20.1.0 eventlet==0.30.2
```

### install Ryu:
```
sudo python3.9 -m pip install ryu
```

### Clone the repo
```
git clone https://github.com/mtd-recon/mtd-recon.git
```

## Usage
### After each start of Mininet, it must be cleaned up with the following command:
```
sudo mn -c
```
### At least two terminals are needed. One terminal is used for the Mininet CLI and the other terminal runs the Ryu controller. 
### The Ryu controller must be started first: 
```
ryu-manager mtd-recon/controller/Ryu_Controller_ip-shuffling_and_port-shuffling_multiple_switches.py
```
```
sudo python3.9 mtd-recon/network/network_multiple_switches.py
```
### To terminate Mininet simply run the command `exit` inside the Mininet CLI
### The Ryu controller automatically terminates if the following Mininet command is entered:
```
sudo mn -c
``` 


## Credits
* [Pascal Kunz](https://github.com/afk-proficoder)
* [Nicholas Mayone](https://github.com/nmayone)
* [Gürkan Gür](https://github.com/gurgurka)
* [Wissem Soussi](https://github.com/wsoussi)



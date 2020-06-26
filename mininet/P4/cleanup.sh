set -e
sudo rm -rf output
sudo rm -rf *.pyc
sudo rm -rf *.pcap
sudo rm -rf *~
sudo rm -rf switch.json
sudo rm -rf /tmp/bm*
sudo rm -rf /tmp/p4s*
sudo mn -c

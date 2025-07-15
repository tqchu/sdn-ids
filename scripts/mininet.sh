sudo myenv/bin/python3 attack.py
sudo myenv/bin/python3 attack.py "sudo hping3 -1 --flood -i u5 " 198.51.100.128

nmap --script vulners -sV -T4 -Pn 198.51.100.128
import nmap

def scan_fortigate_devices(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-p 443 --open')

    fortigate_hosts = []
    for host in nm.all_hosts():
        if nm[host].has_tcp(443):
            if 'open' == nm[host]['tcp'][443]['state']:
                fortigate_hosts.append(host)
    
    return fortigate_hosts


print("Entrer le réseau à scanner x.x.x.x/y")
target_network = input()

print("Scan du réseau " + target_network)

fortigate_devices = scan_fortigate_devices(target_network)

print("\n\n\n Appareils FortiGate détectés dans le réseau {}:".format(target_network))
for device in fortigate_devices:
    print(device)

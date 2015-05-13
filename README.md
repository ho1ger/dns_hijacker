# dns_hijacker
Python script using nfqueue and scapy that demonstrates how to mess with DNS requests:

1 We intercept all DNS queries.
2 We test if the queried Domain Name ends with whateverdomain.
3 If 2 is true we create a faked DNS response that gives back the IP of the local machine.
4 If 2 is not true we just pass the DNS request to the real DNS server.
5 DNS replies are untouched by the script.

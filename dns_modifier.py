#!/usr/bin/python

import nfqueue	as nf
from scapy.all import *
import os

# iptables rules; OUT pc -> sipserver; IN pc <- sipserver

insertOUT	= "iptables -A OUTPUT -j NFQUEUE --queue-num 1 -p udp --dport 53"
insertIN	= "iptables -A INPUT -j NFQUEUE --queue-num 1 -p udp --sport 53"
#insertFW	= "iptables -A FORWARD -j NFQUEUE --queue-num 1 -p udp --dport 53"
flush		= "iptables -F; iptables -X;"

myIP		= "10.0.2.15" #needed to differentiate between incoming / outgoing

def fake_dns_reply(dns_old):
	global myIP

	print "------------- Incoming Query -------------"
	dns_old.show()

	# create the fake response
	dns_new	= DNS(
	id		= dns_old.id,	# msg id
	qr		= 1L,			# Query/Response
	opcode	= dns_old.opcode, 	# Query
	aa		= 0L,			# Auth. Answer
	tc		= 0L,			# Truncenation
	rd		= 1L,			# Rec. Desired
	ra		= 1L,			# Rec. Available
	z		= 0L,			# zero -> reserved
	rcode	= 0L,			# Response code
	qdcount	= dns_old.qdcount,	# Question count
	ancount	= 1,			# Answer count
	nscount	= 0,			# Authoritative record count
	arcount	= 0,			# Additional record count
	qd	= dns_old[DNSQR],	# Question record
	an	= DNSRR(rrname = dns_old[DNSQR].qname, ttl = 2000, rdlen = 4, rdata = myIP),
	ns	= None,
	ar	= None)

	print "------------- Faked Response -------------"
	dns_new.show()
	return dns_new

def callback(i, payload):

	data = payload.get_data()
	pkt=IP(data)

	srcIP = pkt[IP].src
	dstIP = pkt[IP].dst

	if (myIP == srcIP):
		print ">>>>>>>>>>>>>>>>>>>>>>>> OUTGOING PACKET >>>>>>>>>>>>>>>>>>>>>>>>"

		dns = pkt[DNS]
		qname = dns.qd.qname
		if qname.endswith("whateverdomain."):

			# create the fake DNS reply
			dns_new = fake_dns_reply(dns)

			# reverse IP and ports
			src_ip = pkt[IP].src
			dst_ip = pkt[IP].dst
			pkt[IP].src = dst_ip
			pkt[IP].dst = src_ip
			sport = pkt[UDP].sport
			dport = pkt[UDP].dport
			pkt[UDP].sport = dport
			pkt[UDP].dport = sport

			# UDP payload is the new DNS reply
			pkt[UDP].payload = dns_new

			# care for length and checksums
			del pkt[IP].len
			del pkt[IP].chksum
			del pkt[UDP].len
			del pkt[UDP].chksum

			# send response
			payload.set_verdict_modified(nf.NF_ACCEPT, str(pkt), len(pkt))

		else:
			print pkt.summary()
			payload.set_verdict(nf.NF_ACCEPT)

	if (myIP == dstIP):
		print "<<<<<<<<<<<<<<<<<<<<<<<< INCOMING PACKET <<<<<<<<<<<<<<<<<<<<<<<<<"
		print pkt.summary()
		payload.set_verdict(nf.NF_ACCEPT)



if __name__ == "__main__":

	# we have only one queue!
	q = nf.queue()
	q.open()
	q.bind(socket.AF_INET)
	q.set_callback(callback)
	q.create_queue(1)

	# some newlines to better find start of console output...
	for i in range (1,10):
		print "\n"

	try:
		# we have multiple filter rules
		os.system(insertOUT)
		os.system(insertIN)
		q.try_run()

	except KeyboardInterrupt:
		print "exiting"
		q.unbind(socket.AF_INET)
		q.close()

		# flush those nasty rules
		os.system(flush)

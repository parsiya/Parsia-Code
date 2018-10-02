import dpkt, socket
 
f = open('d:\\test1.pcap','rb')
pcap = dpkt.pcap.Reader(f)

counter = 0
 
for ts, buf in pcap:
    
    print "Now processing record number : " + str(counter)
    
    counter +=1
    
    # make sure we are dealing with IP traffic
    # ref: http://www.iana.org/assignments/ethernet-numbers
    try: eth = dpkt.ethernet.Ethernet(buf)
    except: continue
    
    if eth.type != 2048: continue
    # make sure we are dealing with UDP
    # ref: http://www.iana.org/assignments/protocol-numbers/
    try: ip = eth.data
    except: continue
    if ip.p != 17: continue
    # filter on UDP assigned ports for DNS
    # ref: http://www.iana.org/assignments/port-numbers
    try: udp = ip.data
    except: continue
    if udp.sport != 53 and udp.dport != 53: continue
    # make the dns object out of the udp data and check for it being a RR (answer)
    # and for opcode QUERY (I know, counter-intuitive)
    try: dns = dpkt.dns.DNS(udp.data)
    except: continue
    if dns.qr != dpkt.dns.DNS_R: continue
    if dns.opcode != dpkt.dns.DNS_QUERY: continue
    if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
    if len(dns.an) < 1: continue
    # now we're going to process and spit out responses based on record type
    # ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types
    for answer in dns.an:
        if answer.type == 5:
            print "CNAME request", answer.name, "\tresponse", answer.cname
        elif answer.type == 1:
            print "A request", answer.name, "\tresponse", socket.inet_ntoa(answer.rdata)
        elif answer.type == 12:
            print "PTR request", answer.name, "\tresponse", answer.ptrname

print "Number of records in file : " + str(counter)
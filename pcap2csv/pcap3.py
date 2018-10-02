import dpkt, socket
from binascii import hexlify

 
def convert_to_readable_mac( eth_src ) :
    """ converts eth.src and eth.dst to readable mac address """
    
    mac_addr = hexlify(eth_src)
    
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12/2) :     # mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)        # I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return r

 

f = open('d:\\pcap\\BIN_ZeusGameover_2012-02.pcap','rb')
pcap = dpkt.pcap.Reader(f)

counter = 0
 
for ts, buf in pcap:
    
    # print "Now processing record number : " + str(counter)
    
    # print 'Timestamp for record %s is %s' % (counter,ts)
   
    counter +=1
    
    try: eth = dpkt.ethernet.Ethernet(buf)
    except: continue
    
    if eth.type != 2048: continue
    
#    >>> print eth
#    Ethernet(src='\x00\x1a\xa0kUf', dst='\x00\x13I\xae\x84,', data=IP(src='\xc0\xa8\n\n',
#    off=16384, dst='C\x17\x030', sum=25129, len=52, p=6, id=51105, data=TCP(seq=9632694,
#    off_x2=128, ack=3382015884, win=54, sum=65372, flags=17, dport=80, sport=56145)))

    # print ('eth src : %s , eth dest : %s' % (eth_source, eth_dest) )
    
    eth_source = convert_to_readable_mac(eth.src)
    print 'eth_source = ' + eth_source
    
    
    try: ip = eth.data
    except: continue
    
    protocol_number = ip.p 
    # 6 = TCP
    # 17 = UDP
    # ref: http://www.iana.org/assignments/protocol-numbers/
    
    #print "IP is %s" % (ip.p)
    
    if protocol_number != 6 : continue
    
    try: tcp = ip.data
    except: continue
    
    # ref: http://www.iana.org/assignments/port-numbers
    
    source_port = tcp.sport
    dest_port = tcp.dport
 
    # socket.inet_ntoa is to
    # turn source_ip , dest_ip to human readable form
    
    source_ip = socket.inet_ntoa(ip.src)
    dest_ip = socket.inet_ntoa(ip.dst)

    # print 'TCP from %s:%s to %s:%s' % (source_ip, source_port, dest_ip, dest_port)
    
    
#    if source_port == 80:
#        # do stuff
#        
#        print 'http stuff from %s to %s ' % (source_ip, dest_ip)
#    
    # filter stuff based on source and destination port
    
print "Number of records in file : " + str(counter)
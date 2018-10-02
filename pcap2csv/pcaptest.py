'''
pcap test
'''
import dpkt

if __name__ == '__main__':    
    f = open('d:\\pcap\\BIN_ZeusGameover_2012-02.pcap','r')
    pcaphandle = dpkt.pcap.Reader(f)
    
    for ts, buf in pcaphandle:
        eth = dpkt.ethernet.Ethernet(buf)
        # print str(ts) + ' : ' + str(eth)
        ip = eth.data
        tcp = ip.data
        
        print tcp
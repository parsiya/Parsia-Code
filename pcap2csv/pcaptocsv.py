'''
pcap to csv
this will export the data from a pcap file into a csv file to be read by pandas
'''

import sys, dpkt, socket, os.path, datetime
from time import gmtime, strftime   # timestamp stuff
from binascii import hexlify


def convert_to_readable_mac( eth_src ) :
    """ converts eth.src and eth.dst to readable mac addresses - Copied from the internetz"""
    
    mac_addr = hexlify(eth_src)
    
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12/2) :     # mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)        
    return r

# array to hold filenames
filenames = sys.argv[1:]

for filename in filenames:
    try:
        # openning the file
        fileHandle = open(filename,'rb')
        
        # returns fileBase and the extension
        # i.e. for c:\test1.pcap :
        # fileBase =  c:\test
        # fileExtension = .pcap
        # we do this to add .csv at the end of the csv file
        fileBase, fileExtension = os.path.splitext(fileHandle.name)

        # adding .csv at the end of the file path
        # the new file will be in the same path as the old one and will have the extension of csv
        # if you want them anywhere else or with a different extension, you can change it here
        # fileBase = fileBase + '.csv'
        
        # if you want to overwrite the old file , you can comment it out here
        
        newFileName = fileBase + '.csv'
        
        if os.path.exists(newFileName):
            # file exists now we will add timestamp to the name to avoid it again
            # %m = month - %d = day - %Y = 4 digit year - %H = hour in 24hr format - %M = minute - %S = second
            # ref : http://docs.python.org/2/library/time.html#time.strftime
            
            
            timestamp = strftime("-%m-%d-%Y--%H-%M-%S", gmtime()) # timestamp is in the form of  -month-day-year--hour-minute-second
            
            # adding timestamp to the end of the fileame
            fileBase = fileBase + timestamp + '.csv'
            
            # creating a file with timestamp attached if file exists
            fileWriter = open(fileBase ,'w')
            
        # file does not exist
        else:
            fileWriter = open(newFileName,'w')
        
        
        #----------------------------------
        # write csv top line
        # be sure to change it if you change what is included inside
        # don't forget new line '\n' at the end
        
        fileWriter.write('timestamp, source_IP, source_port, destination_ip, destination_port, protocol_name, packet_length\n')
        
        
        #---------------------------------
        # start reading pcap files 
        pcapReader = dpkt.pcap.Reader(fileHandle)
        
        # our string buffer to write records in batches
        stringBuffer = ''
        
        # batch threashold, write x records to file in one batch
        batch_threshold = 100000
        
        # counter to measure the number of stuff
        counter = 0 
        
        # batch counter to print progression
        batch_counter = 0
        
        
        for ts, buf in pcapReader:   
            counter +=1
            
            # ts  : timestamp
            # buf : ethernet data
            
            # converting timestamp from unix time to human readable form
            timestamp = datetime.datetime.fromtimestamp(float(ts))
            
                      
            try: eth = dpkt.ethernet.Ethernet(buf)
            except: continue
            
            if eth.type != 2048: continue
            
            # this is what is supposed to be inside eth, 
            #    >>> print eth
            #    Ethernet(src='\x00\x1a\xa0kUf', dst='\x00\x13I\xae\x84,', data=IP(src='\xc0\xa8\n\n',
            #    off=16384, dst='C\x17\x030', sum=25129, len=52, p=6, id=51105, data=TCP(seq=9632694,
            #    off_x2=128, ack=3382015884, win=54, sum=65372, flags=17, dport=80, sport=56145)))
            
            # this function converts it to MAC address, so you can have the MAC address in proper format
            eth_source = convert_to_readable_mac(eth.src)            
            
            # getting the ip layer data 
            try: ip = eth.data
            except: continue
            
            protocol_number = ip.p 
            # 6 = TCP
            # 17 = UDP
            # ref: http://www.iana.org/assignments/protocol-numbers/
                       
            # this will return something like <class 'dpkt.tcp.TCP'>
            # we will try to extract TCP (or the protocol name out of it)
            protocol_class = str( type(ip.data) )
            
            protocol_name = (protocol_class.split('\''))[1].split('.')[2] 
                        
            # we can filter by protocol here 
            # if protocol_number != 6 : continue
            
            try: transport_layer = ip.data
            except: continue
            
            
            # we can also filter the packets with empty transport layer data length
            
            # if ( len(transport_layer.data < 0 ):
            #    continue
                        
            # ref: http://www.iana.org/assignments/port-numbers
            
            source_port = transport_layer.sport
            dest_port = transport_layer.dport
         
            # socket.inet_ntoa is to
            # turn source_ip , dest_ip to human readable form
            
            source_ip = socket.inet_ntoa(ip.src)
            dest_ip = socket.inet_ntoa(ip.dst)
            
            
            
            #    more filtering if needed 
            
            #    if source_port == 80:
            #        # do stuff
            #        
            #        print 'http stuff from %s to %s ' % (source_ip, dest_ip)
            #    
            #    filter stuff based on source and destination port
            
            
            # -----------------------
            # Writing the gathered data into the file
            
            # timestamp        : timestamp (if you want to format it another way, you can do it here)
            # source_ip        : source IP
            # source_port      : source port
            # dest_ip          : destination IP
            # dest_port        : destination port
            # protocol_name    : protocol name - reference : http://www.iana.org/assignments/protocol-numbers/
            # len(buf)         : length of packet
            
            
            # making a list of stuff to join them for writing
            # simply append anything that you want written
            
            mylist = []
            mylist.append(timestamp)
            mylist.append(source_ip)
            mylist.append(source_port)
            mylist.append(dest_ip)
            mylist.append(dest_port)
            mylist.append(protocol_name)
            mylist.append(len(buf))
            
            stringToWrite = ', '.join( str(item) for item in mylist)
            
            # fileWriter.write(stringToWrite + '\n')
            
            stringBuffer += stringToWrite + '\n'
                        
            # processed one record  (for timestamp, buf ...) 
            
            # writing every batch_threashold records 
            if (counter == batch_threshold):
                 
                # reset counter
                counter = 0
                 
                # write batch to file
                fileWriter.write(stringBuffer)
                 
                # reset stringBuffer
                stringBuffer = ''
                
                batch_counter +=1
            
                # write progression to console    
                print 'Writing records so far ' + str(batch_counter * batch_threshold)
            
            
            # go for next record        
        
        #---------------------------------------------
        # end of one file , go for next file
        
        # write whatever is left in buffer
        
        fileWriter.write(stringBuffer)
                
        fileWriter.close()
        fileHandle.close()
		
		# close file handles and go for next file
           

    # file doesn't exist or not accessible ?!      
    except IOError, e:
        print 'No such file or directory: %s' % e
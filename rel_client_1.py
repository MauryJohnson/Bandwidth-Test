#!/usr/bin/python

# Reliability client for CS 352 
# (c) 2018, R. P. Martin, under GPL Version 2

# this client opens a text files, and send the lines one at a time to a remote echo
# server, and makes sure the MD5 checksum of all the lines sent matches the lines received
from random import randrange, uniform
import argparse
import time
import struct 
import md5
import os 
import sock352
import random
from operator import itemgetter, attrgetter
from difflib import SequenceMatcher

def similar(a,b):
    return SequenceMatcher(None,a,b).ratio()

def main():
    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Socket Client')
    parser.add_argument('-f','--filename', help='File to Echo', required=False)
    parser.add_argument('-d','--destination', help='Destination IP Host', required=True)
    parser.add_argument('-p','--remoteport', help='remote sock352 UDP port', required=False)
    parser.add_argument('-l','--localport', help='local sock352 UDP port', required=True)
    parser.add_argument('-x','--debuglevel', help='Debug Level')
    parser.add_argument('-z','--dropprob', help='Drop Probability')

    
    # get the arguments into local variables
    debug_level = 0 
    args = vars(parser.parse_args())
    filename = args['filename']
    destinationIP = args['destination']
    remote_port = args['remoteport']
    local_port =  args['localport']

    # set the debug level. 0 = no debug statements, 10 = maximum debug output 
    if (args['debuglevel'] == None):
        debug_level = 0
    else:
        debug_level =  int(args['debuglevel'])

    # set the drop probability. 0.0 = no data drops, 1.0 = drop everything 
    if (args['dropprob'] == None):
        probability =  0.0
    else:
        probability =  float(args['dropprob'])

    # open the file for reading
    if (filename):
        try: 
            filesize = os.path.getsize(filename)
            fd = open(filename, "rb")
        except:
            print ( "error opening file: %s" % (filename))
            exit(-1)
    else:
        pass 

    sock352.Client=True
    # max size of the data payload is 63 KB
    MAX_SIZE = (63*1024)

    # max size of the packet with the headers
    MAX_PKT = ((16+16+16)+(MAX_SIZE))

    # create a socket and connect to the remote server
    s = sock352.Socket()

    sock352.CLIENT=True
        
    # set the debug level in the library
    s.set_random_seed(352)
    s.set_debug_level(debug_level)
    s.set_drop_prob(probability)
    
    sock352.drop_prob = probability

    dest_addr = (destinationIP,int(remote_port))
    
    # use the MD5 hash algorithm to validate all the data is correct
    mdhash_sent = md5.new()
    mdhash_recv = md5.new()
    # a lines of lines to echo back 
    lines = fd.readlines()
    rtt_times = []
    
    # for each line, take a time-stamp, send and recive the line, update the list of RTT times,
    # and then update the MD5 hash of the sent and received data
    
    zero_stamp = time.clock()
    
    s.connect(dest_addr)

    s.set_drop_prob(probability)

    num_lines = str(len(lines))
   
    sock352.Lines=int(len(lines))

    E = sock352.Packet()
    E.cntl = 1

    sock352.DATA=int(len(lines))


    S1 = s.sendto('',dest_addr,1,False,False)

	
    #return
    print"DEST ADDR:",dest_addr
    	
    print"RECEIVED INITIALIZE:",S1
   
    end_stamp = time.clock()
    lapsed_seconds = float(end_stamp - zero_stamp)
    line_number = int(num_lines)
    i=0
	
    Average=lapsed_seconds

    print "FIRST MOVING AVERAGE:%.15f " % Average

    #R = sock352.Packet()
    
    print "ALL LINES:",num_lines	
  
    print "DEST:",dest_addr

    print "Probability:",probability
 
    print "SELF PROB:",sock352.drop_prob

    print "LIST OF OUST PACKETS...",sock352.list_of_outstanding_packets




    #sock352.DATA = lines[0]

    #print "DATA SET:",sock352.DATA

    #P = sock352.Packet()

    #S1 = s.sendto(P.toHexFields(),dest_addr,5,False,False)

    #print "FIRST DATA:",S1


    #sock352.DATA = lines[1]

    #print "DATA SET:",sock352.DATA

    #S1 = s.sendto(P.toHexFields(),dest_addr,5,False,False)

    #print "FIRST DATA:",S1

    
    #sock352.DATA = lines[2]

    #print "DATA SET:",sock352.DATA

    #S1 = s.sendto(P.toHexFields(),dest_addr,5,False,False)

    #print "FIRST DATA:",S1


    #return


    Q = sock352.Packet()

    for line in lines:


        start_stamp = time.clock()
        if (debug_level > 0):
            print "rel_client -- sending line %d: %s" % (line_number,line) 

 	sock352.DATA = line

    	print "DATA SET:",sock352.DATA

    	P = sock352.Packet()

    	S1 = s.sendto(P.toHexFields(),dest_addr,5,False,False)

   	print "%d DATA:%s" % (line_number,S1)

	print "SERVER's SYNC:%d CLIENT's SYNC:%d" % (sock352.SYN,sock352.SYNC)

	end_stamp = time.clock() 
        lapsed_seconds = float(end_stamp - start_stamp)
        rtt_times.append(lapsed_seconds) 

  
	#################################
        sock352.SYN = sock352.SYN+1
        #################################	
	
	print "Lapsed seconds:",lapsed_seconds
        line_number = line_number - 1
	print "Lines Left:",line_number

        
	
	# update the sent and received data
	mdhash_sent.update((line))
	Q.data=sock352.DATA
	print "ECHO:",Q.data
        mdhash_recv.update((Q.data))        
        if similar(str(Q.data),line)>=1:
	    print "MATCH!"



	Average = float(sum(rtt_times)) / float(len(rtt_times))

	print "MOVING AVERAGE: %.4f Milisecs" % (Average*1000)
	print "AVG GENERAL:%f " % (Average) 
	print "\n\n\n"

	#i = i+1
    # this allows use to time the entire loop, not just every RTT
    # Allows estimation of the protocol delays
    
    # this part send the lenght of the digest, then the
    # digest. It will be check on the server 
    digest_sent = mdhash_sent.digest()
    digest_recv = mdhash_recv.digest()

    digest_recv2 = mdhash_recv.hexdigest()

    print "DIGEST RECV:",digest_recv

    Y = sock352.Packet()

    Y.cntl = 6
    #print "\n FINAL DIGEST:\n:",digest_recv[0]
    Y.data = str(digest_recv2)
   
    #send = s.sendto(str(Y.toHexFields()),(str(Y.data),dest_addr),6)

    s.close()
    final_stamp = end_stamp

    
    # compute RTT statisticis
    rtt_min = min(rtt_times)
    rtt_max = max(rtt_times)
    rtt_ave = float(sum(rtt_times)) / float(len(rtt_times))
    total_time = final_stamp - zero_stamp                                           
                                           
    print ("rel_client: echoed %d messages in %0.6f millisec min/max/ave RTT(msec) %.4f/%.4f/%.4f " %
           (len(lines), total_time*1000, rtt_min*1000,rtt_max*1000,rtt_ave*1000))


    # compare the two digests, byte for byte
    failed = False;
    for i, sent_byte in enumerate(digest_sent):
        recv_byte = digest_recv[i]
        #print "Recv:%x Sent:%x",recv_byte,sent_byte
	if (sent_byte != recv_byte):
            print( "rel_client: digest failed at byte %d diff: %c %c " % (i,sent_byte,recv_byte))
            failed = True;
    if (not failed):
        print( "echo_client: digest succeeded")
    
    fd.close()
                                           
# this gives a main function in Python
if __name__ == "__main__":
    main()
# last line of the file 

#!/usr/bin/python

# echo server for CS 352 
# (c) 2018, R. P. Martin, under GPL Version 2

# this sever echos back whatever it gets, up to the max of sock352.MAX_SIZE

import argparse
import time
import struct 
import md5
import os 
import sock352

MAX_SIZE = sock352.MAX_SIZE

def main():
    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Socker Echo Server ')
    parser.add_argument('-l','--localport', help='local sock352 UDP port', required=True)
    parser.add_argument('-x','--debuglevel', help='Debug Level')
    parser.add_argument('-z','--dropprob', help='Drop Probability')
    
    args = vars(parser.parse_args())
    local_port =  int(args['localport'])

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


    sock352.CLIENT=False

    serverSock = sock352.Socket()
    serverSock.bind(('', local_port))

    # set the debug level in the library
    serverSock.set_random_seed(352)
    serverSock.set_debug_level(debug_level)
    serverSock.set_drop_prob(probability)

    #L = serverSock.listen(0)

    #print "ACCEPT:",L
	
    #from_addr = serverSock.accept()
    
    #print "Accepted",from_addr	
#INIT
    #sock352.Client=False
	
    sock352.drop_prob=probability

    RECV = serverSock.recvfrom(MAX_SIZE,0)

    print "RECV 000:",RECV


    #return

    P = sock352.Packet()
    sock352.ParsePack(RECV[0],P)    
    sock352.SYNC = P.seq
    sock352.SetSock(P,P.cntl,P.data,True)


    print "Server Sends Listen to client:",sock352.PrintPack(P)

    serverSock.sendto(P.toHexFields(),RECV[1],3,True,False)

    print "Server--Client connection established."

    line_count = int(sock352.DATA)


    
    #S2 = serverSock.sendto(P.toHexFields(),RECV[1],5,True,False)

    #print "SERVER's SYNC:%d CLIENT's SYNC:%d" % (sock352.SYN,sock352.SYNC)
    
    #################################
    #sock352.SYNC = sock352.SYNC+1
    ################################# 
    
    #S2 = serverSock.sendto(P.toHexFields(),RECV[1],5,True,False)

    #print "SERVER's SYNC:%d CLIENT's SYNC:%d" % (sock352.SYN,sock352.SYNC)    
    #################################
    #sock352.SYNC = sock352.SYNC+1
    #################################

    #S2 = serverSock.sendto(P.toHexFields(),RECV[1],5,True,False)

    #print "SERVER's SYNC:%d CLIENT's SYNC:%d" % (sock352.SYN,sock352.SYNC)

    #return

    while (line_count > 0):
        #Read from UDP socket into message, client address 
        #message = serverSock.recvfrom(MAX_SIZE,None)
        #print ("server -- got packet len %d line %s" % (len(message[0]),message))
	start_stamp=time.clock()

        S2 = serverSock.sendto(P.toHexFields(),RECV[1],5,True,False)
        print "SERVER's SYNC:%d CLIENT's SYNC:%d" % (sock352.SYN,sock352.SYNC)

	print "\n\nDATA GOT:",S2

	end_stamp = time.clock()
	lapsed_seconds = float(end_stamp - start_stamp)
        sock352.RTT_TIMES.append(lapsed_seconds)

	sock352.RTT =  float(sum(sock352.RTT_TIMES)) / float(len(sock352.RTT_TIMES))

	print "SERV EST DATA LAPSED SECONDS:",lapsed_seconds

	#################################
        sock352.SYNC = sock352.SYNC+1
        #################################

	line_count = line_count - 1
        print ("server -- %d lines to go " % (line_count))
        print "\n\n\n"
	#return
    #time.sleep(2)
    #message = serverSock.sockett.recvfrom(MAX_SIZE)  
    Close = False
	
    #while(not Close):
	
        #print "LAST RECV",message
        #time.sleep(4)
        #serverSock.sockett.sendto(str(Q.toHexFields()),(Host,Port))



    #serverSock.sockett.sendto(str(Q.toHexFields()),(Host,Port))

    #serverSock.close()

# this gives a main function in Python
if __name__ == "__main__":
    main()

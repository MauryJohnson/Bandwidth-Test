#!/usr/bin/python

# Reliability client for CS 352 
# (c) 2018, R. P. Martin, under GPL Version 2

# this client opens a text files, and send the lines one at a time to a remote echo
# server, and makes sure the MD5 checksum of all the lines sent matches the lines received

import argparse
import time
import struct 
import md5
import os
import sys
import binascii
import sock352


REALSYNC = 0

rtt_times = []

def TIME(Z):
    global rtt_times
    end_stamp = time.clock()
    lapsed_seconds = float(end_stamp - Z)
    rtt_times.append(lapsed_seconds)

    rtt_ave = float(sum(rtt_times)) / float(len(rtt_times))
    sock352.RTT=rtt_ave
    return rtt_ave
    

def PrintPack(P):
    print "P CNTL:",P.cntl

    print "P SEQ:",P.seq

    print "P ACK:",P.ack

    print "P SIZE:",P.size

    print "P DATA:",P.data
    return

def ParsePack(Str,P):
    i=0
    Next=0
    str2 = ""
    str3 = "D"
    str1 = '0'
    for s in Str:
        if s==':':
	    i=1
	    str2=""
	    continue          
	elif s=='x':
	    i=0
	    #print "HEX DIGIT:",str2
	    if len(str2)<2:
                str1 = str1+str2
                str2 = str1
                str1 = '0'
            print "HEX DIGIT:",str2
	    if Next==1:
	        P.cntl=int(str2)
	    if Next==2:
	        P.seq=int(str2)
            if Next==3:
 		P.ack=int(str2)
            if Next==4:
		P.size=int(str2)
            if Next==5:
		P.data=int(str2)
	    Next=Next+1	
	    str3=str3+"\\"+str2
 	    continue
	elif i==1:
	    str2+=s
    print "FINAL HEX:",str3
    return	 

def main():
    global REALSYNC
    # parse all the arguments to the client
    if (sys.argv[0]): 
        prog_name = sys.argv[0]
    else:
        prog_name = 'rel_bw_test.py'

        
    parser = argparse.ArgumentParser(description='CS 352 Socket Client')
    parser.add_argument('-f','--filename', help='File to Echo', required=False)
    parser.add_argument('-d','--destination', help='Destination IP Host', required=True)
    parser.add_argument('-p','--remoteport', help='Remote sock352 UDP port', required=False)
    parser.add_argument('-l','--localport', help='Local sock352 UDP port', required=True)
    parser.add_argument('-s','--server', help='Run as server', action='store_true')
    parser.add_argument('-x','--debuglevel', help='Debug Level')
    parser.add_argument('-z','--dropprob', help='Drop Probability')
        
    # get the arguments into local variables 
    args = vars(parser.parse_args())
    filename = args['filename']
    destinationIP = args['destination']
    remote_port = args['remoteport']
    local_port =  int(args['localport'])
    run_as_server = args['server']


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
    #if (filename):
        #try: 
            #filesize = os.path.getsize(filename)
            #fd = open(filename, "rb")
        #except:
            #print ( "error opening file: %s" % (filename))
            #exit(-1)
    #else:
        #pass 


    #rtt_times = []

    # create a socket and connect to the remote server
    s = sock352.Socket()
    
    dest_addr = (destinationIP,int(remote_port))
    
    # use the MD5 hash algorithm to validate all the data is correct
    mdhash_sent = md5.new()
    mdhash_recv = md5.new()
    # a lines of lines to echo back
    
    # for each line, take a time-stamp, send and recive the line, update the list of RTT times,
    # and then update the MD5 hash of the sent and received data

    # the maximum packet size for this transfer is 4K
    max_pkt_size = (4*1024)
    # set the debug level in the library
    s.set_random_seed(352)
    s.set_debug_level(debug_level)
    s.set_drop_prob(probability)
    
    # start time stamp to compute the bandwidth 
    zero_stamp = start_stamp = time.clock()

    print "START STAMP:",start_stamp

    ADDR = 0

    SERVER = False

    # run as a client or server 
    if (run_as_server):
        s.bind(('', local_port))
        #from_addr = s.accept()
	#ADDR = from_addr
	SERVER = True
    else:
        #s.connect(dest_addr)
    	ADDR = dest_addr
    # the first message is the file size to send 
    #print "BYTES SEND:",bytes_to_send
  
    lines = ' ' 

    filesize=0


    if (filename and SERVER==False):
        try:
            filesize = os.path.getsize(filename)
            fd = open(filename, "rb")
	    lines = fd.readlines()
	    #fileinput.input(filename,inplace=1,mode="rb")
	except:
            print ( "error opening file: %s" % (filename))
            exit(-1)
    else:
        pass
	
	
    bytes_to_send=0
    R = sock352.Packet()
    send = 0
    recv_size=0

    #lines = fd.readlines()
    
    num_lines = str(len(lines))

    #zero_stamp = time.clock()

    bytes_to_receive = 0

    zero_stamp = time.clock()

    s.set_drop_prob(probability)

    sock352.drop_prob=probability

    SYNCH = sock352.SYNC


    from_addr = 0
    #filesize=0
    if SERVER==False:
	#print "FILE:",lines
        #sock352.Client=False
	sock352.DATA=filesize
	
	bytes_to_send=bytes_to_receive = int(filesize)
		
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

    	print "ALL LINES:",filesize

    	print "DEST:",dest_addr

    	print "Probability:",probability

    	print "SELF PROB:",sock352.drop_prob

    	print "LIST OF OUST PACKETS...",sock352.list_of_outstanding_packets
	
	SYNCH = sock352.SYNC

	#bytes_
         	
	#recv_size=int(R.data)
	#bytes_to_receive = filesize
	#bytes_to_send = bytes_to_receive
    else:
        RECV = s.recvfrom(max_pkt_size,0)

        print "RECV 000:",RECV

	P = sock352.Packet()
        sock352.ParsePack(RECV[0],P)
        sock352.SYNC = P.seq
        sock352.SetSock(P,P.cntl,P.data,True)

	print "Server Sends Listen to client:",sock352.PrintPack(P)

	from_addr = RECV[1]

        s.sendto(P.toHexFields(),RECV[1],3,True,False)

        print "Server--Client connection established."

        bytes_to_send=bytes_to_receive = int(sock352.DATA)

	


    #sock352.drop_prob=probability	
    end_stamp = time.clock()    

    lapsed_seconds = float(end_stamp - zero_stamp)
    Average=lapsed_seconds
	
    print "FIRST MOVING AVERAGE:%.15f:" % Average

    print"DEST ADDR:",dest_addr
    
    #FOR CLIENT
    SEND1 = ''
    #FOR SERVER
    SEND2 = ''	
 
    print "BYTES TO RECEIVE:",bytes_to_receive
    print "BYTES TO SEND:",bytes_to_send
    #return 
    # loop until there are no bytes left to send or receive
    i = 0

    recv_data=0

    Host  =''

    Port = 0

    end_stamp = time.clock()
    lapsed_seconds = float(end_stamp - zero_stamp)

    print "MOVING AVG:",lapsed_seconds

    print "DROP PROB:",probability
    
    print "TOTAL FILE SIZE:",filesize

    print "SERVER'S SYNC",sock352.SYN
    print "CLIENT's SYNC:",sock352.SYNC

    #return

    if SERVER == True:

	#global sock352.SYNC

        print "SERVER SIDE"
	total_bytes=bytes_to_receive
	#Q=sock352.Packet()
	#NEX = int(sock352.SYNC)+1
	#print "NEXT:",NEX
	##############################   
	#sock352.SYNC = NEX
        ##############################
	while ((bytes_to_send > 0)):
      
            print "BYTES TO SEND LEFT:",bytes_to_send 
	    print "BYTES TO RECEIVE LEFT:",bytes_to_receive
	
	    if (bytes_to_send >= max_pkt_size):
                size_to_send = max_pkt_size 
            else:
                size_to_send = bytes_to_send

	    #T=sock352.Packet()
                
	    #T=Q
		
	    start_stamp = time.clock()

	    S2 = s.sendto(P.toHexFields(),from_addr,5,True,False)

	    #return

	    print "SERVER's SYNC:%d CLIENT's SYNC:%d" % (sock352.SYN,sock352.SYNC)

            #print "\n\nDATA GOT:",S2

            end_stamp = time.clock()
            lapsed_seconds = float(end_stamp - start_stamp)
            sock352.RTT_TIMES.append(lapsed_seconds)

            sock352.RTT =  float(sum(sock352.RTT_TIMES)) / float(len(sock352.RTT_TIMES))

            print "SERV EST DATA LAPSED SECONDS:",lapsed_seconds


            #################################
            #sock352.SYNC = sock352.SYNC+1
            sock352.IncrSYNC()
	    #################################


            bytes_to_send = bytes_to_send - len(sock352.DATA)

	    bytes_to_receive = bytes_to_receive - len(S2)

	    #TT=binascii.hexlify(T.data)
                
	    mdhash_sent.update(binascii.hexlify(sock352.DATA))
		
	    mdhash_recv.update(binascii.hexlify(S2))

	    #break
            i = i +1
            if ((i % 100) == 0 ):
                print ".",
	    print "BYTES TO SEND LEFT 2:",bytes_to_send
	    #break
	    #if i==1000:
		    #return
		#print "BYTES TO RECEIVE LEFT:",bytes_to_receive
		#print "THE DATA SENT:",T.data
            #if(bytes_to_receive > 0):
	        #print "BYTES TO RECEIVE LEFT:",bytes_to_receive
		#message  = s.sockett.recvfrom(max_pkt_size)
	
                #mdhash_recv.update(QQ)
	                

    else:
 	fd.seek(0)
	print "CLIENT SIDE"
	total_bytes=bytes_to_send
	R = sock352.Packet()
	
	SYNCH = sock352.SYNC

	REALSYNC=SYNCH

	while ( (bytes_to_send > 0) ):
	    #global sock352.SYNC     
	        
            print "\n\nBYTES TO RECEIVE LEFT:",bytes_to_receive
	    print "\n\nBYTES TO SEND LEFT:",bytes_to_send
 
	    if (bytes_to_send >= max_pkt_size):
                size_to_send = max_pkt_size 
            else:
                size_to_send = bytes_to_send
                bytes_to_receive=size_to_send
	    #R.cntl=start_stamp = time.clock()
	        
	    X = fd.read(size_to_send)
		
	    sock352.DATA = X

	    #print "X DATA:",X

            #break
	
	    S1 = s.sendto(R.toHexFields(),dest_addr,5,False,False)	
        
	    ################################# 
	    sock352.SYN = sock352.SYN +1
	    #################################

	  #return
    
            print "SERVER's SYNC:%d CLIENT's SYNC:%d" % (sock352.SYN,sock352.SYNC)

            #print "%d\nDATA1:%s \nDATA 2:%s" % (size_to_send,S1,X)
	    
       	    #print "SERVER's SYNC:%d CLIENT's SYNC:%d" % (sock352.SYN,sock352.SYNC)

	    end_stamp = time.clock()
	    lapsed_seconds = float(end_stamp - start_stamp)
            rtt_times.append(lapsed_seconds)
		

            print "Lapsed seconds:",lapsed_seconds

		
            Average = float(sum(rtt_times)) / float(len(rtt_times))
            print "MOVING AVERAGE: %.4f Milisecs" % (Average*1000)
       	    print "AVG GENERAL:%f " % (Average)
            print "\n\n\n"

        
	    #sock352.rtt_times=rtt_times
	    #Successfully received data
	    bytes_to_send=bytes_to_send - len(sock352.DATA)
  	    bytes_to_receive=bytes_to_receive - len(X)
	    #RR = binascii.hexlify(R.data)
  	    #print "R",R.data
	    #print "Y",Y.data	

	    mdhash_recv.update(binascii.hexlify(X))
	    mdhash_sent.update(binascii.hexlify(sock352.DATA))
            
	
	    #return
	    #send_data = fd.read(size_to_send)     
            #send = s.sendto(send_data)
            #bytes_to_send = bytes_to_send - size_to_send
            #mdhash_sent.update(send_data)
            i = i +1
            if ((i % 100) == 0 ):
                print ".",
            rtt_ave = float(sum(rtt_times)) / float(len(rtt_times))
	    print "CURR RTT AVG + offset:",rtt_ave
	    #sock352.RTT=Average
	
	    #break
	 
            #if (bytes_to_receive > 0):
                #recv_data = s.recvfrom(max_pkt_size)
                #bytes_to_receive = bytes_to_receive - len(recv_data)
                #mdhash_recv.update(recv_data)                    


        print "\n\n\n"
	#s.sendto("ACK",dest_addr)
    #return
    print "MADE IT"
    
    digest_sent = mdhash_sent.digest()
    digest_recv = mdhash_recv.digest()
 
    print "MADE IT"
   
    sock352.list_of_outstanding_packets = []
 
    #FINAL SEND TO ACKNOWLEDGE ALL DATA
   # send = s.sockett.sendto(digest_recv,RECV,5)
    # REMOTE DIGEST IS OTHER's DIGEST RECEIVED, ECHO
    #remote_digest = s.recvfrom(max_pkt_size)
    
    #return

    #send = s.sendto(digest_recv,RECV,6)
    if(SERVER):


	print "RECEIVE"
	Found = False
	remote_digest = 0
	remote_digest1 = 0
        while (not Found):
            remote_digest1 = s.recvfrom(max_pkt_size,0)
	    print "REMOTE DIG:",remote_digest1
            try:
                Found = True
                remote_digest = binascii.unhexlify(remote_digest1[0])
            except:
                Found = False
       
        P = sock352.Packet()
	sock352.SetSock(P,1,'',True)
	P.cntl = 8 
	print "FINAL PACK:",sock352.PrintPack(P)	
	s.sockett.sendto(P.toHexFields(),from_addr)
	#return 	
    	#remote_digest1 = s.sockett.recvfrom(max_pkt_size)

 	#remote_digest1 = s.sockett.recvfrom(max_pkt_size)	

        P = sock352.Packet()

    	#print "REMOTE DIGEST 1:",remote_digest1   
 
   	#sock352.ParsePack(remote_digest1[0],P)

	Dig = binascii.hexlify(digest_sent)

	#sock352.ParsePack(remote_digest1[0],P)

	#print "P DIGEST:",P.data

	print "MY DIGEST:",Dig

	#return

    	#remote_digest = binascii.unhexlify(P.data)
	
	#Found = False
	#while (not Found):
	    #remote_digest1 = s.sockett.recvfrom(max_pkt_size)
	    #try:
		#Found = True
		#remote_digest = binascii.unhexlify(remote_digest1)
	    #except:
	        #Found = False
	#print "REMOTE_DIGEST",remote_digest	

	s.close()            
        end_stamp = time.clock()
        lapsed_seconds = float(end_stamp - zero_stamp)
        #fd.close()
    
        #print "MADE IT"

        print "rel: sent digest: x%s received digest x%s remote digest x%s " % (binascii.hexlify(str(digest_sent)), binascii.hexlify(str(digest_recv)), binascii.hexlify(str(remote_digest)))

        # this part send the lenght of the digest, then the
    	# digest. It will be check on the server 

    	# compute bandwidthstatisticis
   	total_time = float(end_stamp) - float(zero_stamp)                                        
    	print "TOTAL TIME:%.10f" % total_time

    	#return
    	try: 
	    bandwidth = ((total_bytes)/ (total_time))/1000000.0
    	except: 
	    print "ERROR, DIVIDE BY 0" 
            return
    	# make sure the digest from the remote side matches what we sent
        failed = False;
        for i, sent_byte in enumerate(digest_sent):
            remote_byte = remote_digest[i]
            if (sent_byte != remote_byte):
                print( "%s: digest failed at byte %d diff: %c %c " % (prog_name,i,sent_byte,remote_byte))
                failed = True;
        if (not failed):
            print( "%s: digest succeeded bandwidth %f Mbytes/sec" % (prog_name,bandwidth) )

    else:
	fd.close()
        digest_sent = mdhash_sent.digest()
        
	digest_recv = mdhash_recv.digest()

        digest_recv2 = mdhash_recv.hexdigest()

	Dig = binascii.hexlify(digest_recv)

	Dig2 = binascii.hexlify(digest_sent)

        print "DIGEST RECV:",Dig
	print "DIGEST SENT:",Dig2

        Y = sock352.Packet()

        Y.cntl = 6
        #print "\n FINAL DIGEST:\n:",digest_recv[0]
        Y.data = str(digest_recv2)

	while(1):

    	    send = s.sockett.sendto(Dig,dest_addr)
	    try:
	        R1 = s.recvfrom(max_pkt_size,0)
	    except:
		  print "Waited too long..."
	    sock352.ParsePack(R1[0],Y)
	    #sock352.PrintPack(Y)	
	    if(Y.cntl==8):
	        print "Final Packet, confirmed"
		break
	#send = s.sendto(str(Y.toHexFields()),(str(Y.data),dest_addr),6)


	#return 	
    	s.close()
    	final_stamp = end_stamp

	#digest_recv=binascii.unhexlify(digest_recv2)

    	# compute RTT statisticis
    	rtt_min = min(rtt_times)
    	rtt_max = max(rtt_times)
    	rtt_ave = float(sum(rtt_times)) / float(len(rtt_times))
    	total_time = final_stamp - zero_stamp

    	print ("rel_client: echoed %d bytes in %0.6f millisec min/max/ave RTT(msec) %.4f/%.4f/%.4f " %
               (total_bytes, total_time*1000, rtt_min*1000,rtt_max*1000,rtt_ave*1000))


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
	E = sock352.Packet()
	#S = s.sendto(E.toHexFields(),dest_addr,8,False,False)
	



    # this makes sure all threads exit 
    os._exit(1)
    
# create a main function in Python
if __name__ == "__main__":
    main()

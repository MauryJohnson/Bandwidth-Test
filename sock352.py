# sock352.py 

#from operator import itemgetter, attrgetter, methodcaller
from random import randrange, uniform
import socket as ip
import random
import binascii
import threading
import time
import sys
import struct as st
import os, re
import signal
import struct
from difflib import SequenceMatcher
from io import StringIO
import subprocess


SYN = 0
SYNC = 0
SYNC2 = 0

#_split = re.compile(r'[\0%s]' % re.escape(''.join(
    #[os.path.sep, os.path.altsep or ''])))
def similar(a,b):
    return SequenceMatcher(None,a,b).ratio()

def raw(text):
    """Returns a raw string representation of text"""
    return "".join([escape_dict.get(char,char) for char in text])

def word_to_int(hex_str):
    value = int(hex_str, 16)
    if value > 127:
        value = value-256
    return value

def bytes_to_int(bytes):
    result = 0

    for b in bytes:
        result = result * 256 + int(b)

    return result

def PrintPack(P):
    print "P CNTL:",P.cntl

    print "P SEQ:",P.seq

    print "P ACK:",P.ack

    print "P SIZE:",P.size

    print "P DATA:",P.data
    return

def IncrSYNC():
    global SYNC
    SYNC = SYNC+1
    return

def SetSock(P,CNTL,DATA,Server):
    global SYNC
    global SYN
    global SYNC2
    #SYNC2 = SYNC
    G = random.sample(xrange(2222,10000),60)
    G = random_no_repeat1(G,60)
    if CNTL==STATE_INIT and not Server:
        P.cntl=CNTL
	P.seq=G[10]	
	P.ack=0
	P.size=0
    if CNTL==STATE_SYNSENT and not Server:
   	#P.seq=0
	P.ack=P.seq
	P.seq=0
	P.size=0
	P.cntl=CNTL	
    if CNTL==STATE_LISTEN and not Server:
	P.cntl=CNTL
	P.seq=G[11]
	#P.ack = P ACK WILL BE SET AS THE SEQ OF PACKET IT GOT
	P.size=0	
    if CNTL==STATE_SYNRECV and not Server:
	#print "\n\n\n\nDATA TO ADD TO SEND:",DATA
        P.data=DATA
	#P.size=len(DATA)
	P.cntl=CNTL
	P.ack = 0
	P.seq=G[21]	
    if CNTL==STATE_ESTABLISHED and not Server:
	#global SYNC
	P.cntl = 4
	P.data=DATA
	P.ack=0
	P.size = len(DATA)
	T = SYNC+1
	print "SYNC BEFORE:",SYNC
	#SYNC +=1
	IncrSYNC()
	SYNC2 = SYNC2+1
	print "SYNC AFTER:",SYNC
	if T!=SYNC:
	    print "ERROR, SYNC NOT INCRE"
	    exit(-1)
	else:
	    print "\n\n\n\n\nSYNC SET:%d T:%d" %(SYNC,T)
	P.seq = SYNC2
    if CNTL==STATE_CLOSING and not Server:
	P.cntl = CNTL
	P.data = ''
	P.size = 0
	P.ack = 0
	P.seq = SYNC
	
    #if CNTL==STATE_CLOSED:

    #if CNTL==STATE_REMOTE_CLOSED:
    if CNTL==STATE_INIT and Server:
        P.cntl=3
        #P.seq=G[10]
        P.ack=P.seq
	P.seq=G[10]
        P.size=0
    if CNTL==STATE_SYNSENT and Server:
        P.seq=0
        P.ack=G[3]
        P.size=0
        P.cntl=CNTL
    if CNTL==STATE_LISTEN and Server:
        P.cntl=CNTL
        P.seq=G[11]
        #P.ack = P ACK WILL BE SET AS THE SEQ OF PACKET IT GOT
        P.size=0
    if CNTL==STATE_SYNRECV and Server:
        #print "\n\n\n\nDATA TO ADD TO SEND:",DATA
        #P.data=DATA
        #P.size=len(DATA)
        P.cntl=2
        P.ack = P.seq
        P.seq = 0
	P.data=''
	P.size=0
    if CNTL == STATE_ESTABLISHED and Server:
  	#IncrSYNC()
	P.seq = SYNC
	#P.data = DATA
	P.ack = 0
	#P.size=len(DATA)
	P.cntl = 4
    if CNTL == 6 and Server:
	P.data = DATA
	#SYN = SYN +1
	P.seq = SYN+1
	P.cntl  = 4
	P.size = len(DATA)
	P.ack = 0
    return

def RemoveAll(packet,address):
    global list_of_outstanding_packets
    P = Packet()
    for i in list_of_outstanding_packets:
	ParsePack(i[0],P)
	if P.seq < SYNC:
	    list_of_outstanding_packets.remove(i)
        if similar(i[0],packet)==1 and similar(i[1],address):
	    list_of_outstanding_packets.remove(i)
    return

def ParsePack(Str,P):
    i=0
    Next=0
    str2 = ""
    str3 = "D"
    str1 = '0x0'
    for s in Str:
        if s=='x':
            i=1
            str2=""
            continue
        elif s==' ':
            i=0
	    if Next==1:
                P.cntl=((int(str2,16)))
		#P.cntl=((binascii.unhexlify(str2)))
	    if Next==2:
                print ""
		#P.seq=((binascii.unhexlify(str2)))
		P.seq=((int(str2,16)))
            if Next==3:
                P.ack=int(str2,16)
            if Next==4:
                P.size=int(str2,16)
            if Next==5:
                P.data=int(str2,16)
            Next=Next+1
            str3=str3+'\\'+str2
            continue
        elif i==1:
            str2+=s
    #print "Str2:",str2	
	
    B = ''	

    try: 
	B=((binascii.unhexlify(str2)))
    except:
	str2 = str2+'0'
	B=((binascii.unhexlify(str2)))
    #P.data = int(str2.encode('hex'),16)
    #P.data = P.data
    Next=Next+1
    str3=str3+'\\'+str2
    #print "FINAL HEX:",str3
    
    #print "DATA:",B
    
    #print "SUPPOSED TO BE DATA:",str2
    P.data=B
    return B

def random_no_repeat1(numbers, count):
    """
    >>> import random
    >>> random.seed(0)
    >>> random_no_repeat1(range(12), 10)
    [1, 9, 8, 5, 10, 2, 3, 7, 4, 0]
    """
        #P.cntl=CNTL

	
    return
def ParsePack(Str,P):
    i=0
    Next=0
    str2 = ""
    str3 = "D"
    str1 = '0x0'
    for s in Str:
        if s=='x':
            i=1
            str2=""
            continue
        elif s==' ':
            i=0
	    if Next==1:
                P.cntl=((int(str2,16)))
		#P.cntl=((binascii.unhexlify(str2)))
	    if Next==2:
                print ""
		#P.seq=((binascii.unhexlify(str2)))
		P.seq=((int(str2,16)))
            if Next==3:
                P.ack=int(str2,16)
            if Next==4:
                P.size=int(str2,16)
            if Next==5:
                P.data=int(str2,16)
            Next=Next+1
            str3=str3+'\\'+str2
            continue
        elif i==1:
            str2+=s
    #print "Str2:",str2	
	
    B = ''	

    try: 
	B=((binascii.unhexlify(str2)))
    except:
	str2 = str2+'0'
	B=((binascii.unhexlify(str2)))
    #P.data = int(str2.encode('hex'),16)
    #P.data = P.data
    Next=Next+1
    str3=str3+'\\'+str2
    #print "FINAL HEX:",str3
    
    #print "DATA:",B
    
    #print "SUPPOSED TO BE DATA:",str2
    P.data=B
    return B

def random_no_repeat1(numbers, count):
    """
    >>> import random
    >>> random.seed(0)
    >>> random_no_repeat1(range(12), 10)
    [1, 9, 8, 5, 10, 2, 3, 7, 4, 0]
    """
    number_list = list(numbers)
    random.shuffle(number_list)
    return number_list[:count]


#CLIENT = False

#For Client

bytes_to_receive = 0

Lines = 0

#rtt_times []
#Will alter depending on average rtt
RTT = 0

MULTIPLIER = 2

THRESHOLD = 0.8

TCOUNT = 0

RTT_TIMES = []

list_of_outstanding_packets=list()

list_of_successful_packets=list()

sock352_dbg_level = 0

drop_prob = 0.0

# The first byte of every packet must have this value 
MESSAGE_TYPE = 0x44

# this defines the sock352 packet format.
# ! = big endian, b = byte, L = long, H = half word
HEADER_FMT = '!bbLLH'

# this are the flags for the packet header 
#SYN =  0x01    # synchronize 
#SYN = 0x00
#SYNC = 0x00
#ACK =  0x02    # ACK is valid 
ACK = 0x00
#DATA = 0x04    # Data is valid 
DATA= 0x00
#FIN =  0x08    # FIN = remote side called close 
FIN = 0x08

# max size of the data payload is 63 KB
MAX_SIZE = (63*1024)

# max size of the packet with the headers 
MAX_PKT = ((16+16+16)+(MAX_SIZE))

# these are the socket states 
STATE_INIT = 1
STATE_SYNSENT = 2
STATE_LISTEN  = 3
STATE_SYNRECV = 4 
STATE_ESTABLISHED = 5
STATE_CLOSING =  6
STATE_CLOSED =   7
STATE_REMOTE_CLOSED = 8

# function to print. Higher debug levels are more detail
# highly recommended 
def dbg_print(level,string):
    global sock352_dbg_level 
    if (sock352_dbg_level >=  level):
        print string 
    return 

# this is the thread object that re-transmits the packets 
class sock352Thread (threading.Thread):
    
    def __init__(self, threadID, name, delay):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = float(delay)
        
    def run(self):
	global list_of_successful_packets
        dbg_print(3,("sock352: timeout thread starting %s delay %.3f " % (self.name,self.delay)) )
        scan_for_timeouts(self.delay)
        print "\n\nEND TIMEOUTS SCANS(S)\n\n"
        dbg_print(3,("sock352: timeout thread %s Exiting " % (self.name)))
	list_of_successful_packets = []
	return

def scan_for_timeouts(delay):
    #L = list()
    global list_of_outstanding_packets

    #list_of_outstanding_packets.append("HELO")

    time.sleep(delay)

    # there is a global socket list, although only 1 socket is supported for now
    while ( True ):

        time.sleep(delay)
        # example
        for packet in list_of_outstanding_packets:

            current_time = time.time()
            time_diff = float(current_time) - float(packet[2])
            dbg_print(5,"sock352: packet timeout diff %.3f %f %f " % (time_diff,current_time,packet[2])) #THIRD skbuf.time_sent
            if (time_diff > delay and PacketFound(packet[0],packet[1])==False):
                dbg_print(3,"sock352: packet timeout, retransmitting")
                P = Packet()
                S=Socket()
		ParsePack(packet[0],P)
                address = packet[1]
                
                print "SENDING STATE MUST MATCH RECV STATE OF IT FOR SENDTO FUNC!"
            
                print "THREAD PACK RESEND:",packet
                S.sendto(packet[0],(address[0],address[1]),packet[3],packet[4],True)
                # Resend packet with same permission as previously
            elif PacketFound(packet[0],packet[1])==True:
                print "PACKET SUCCESSFULLY MADE IT"
                RemoveAll((packet[0],packet[1]))
                print "RETURN?"
        if(len(list_of_outstanding_packets)==0):
            print "LIST:",list_of_outstanding_packets
            print "No more packets outstanding, return"
            break
	    #stop_event.set()
        print "WHILE(TRUE)"
    return

def roll(die,sides):  # Define roll function
    r = 0  # Start r at 0 since most people don't know to count 0 as 1, 1 as 2, etc
    while r < die:  # Start While loop to roll based on number of dice selected
        rolls = random.uniform(0,1)  # Store random roll to variable rolls
        r += 1  # Increase r by 1 each loop through until loop validates false
        print("You Rolled a:", rolls)  # Print out the rolls for each die selected
    return rolls

def PacketFound(Packet,address):
    #print "Searching if Packet and address were already successfully sent"
    global list_of_successful_packets
    for i in list_of_successful_packets:
        #print "%s Compared to:%s" %(i,(Packet,address))
	if similar(i[0],Packet)==1 and similar(i[1],address)==1:
	    print "Found already successful packet send"
	    return True
    print "Could not find successful packet send... Continue to send delayed packet."	
    return False

# This class holds the data of a packet gets sent over the channel 
# 
class Packet:
    def __init__(self):
        self.type = MESSAGE_TYPE    # ID of sock352 packet
        self.cntl = 0               # control bits/flags 
        self.seq = 0                # sequence number 
        self.ack = 0                # acknowledgement number 
        self.size = 0               # size of the data payload 
        self.data = b''             # data 

    # unpack a binary byte array into the Python fields of the packet 
    def unpack(self,bytes):
        # check that the data length is at least the size of a packet header 
        data_len = (len(bytes) - st.calcsize('!bbLLH'))
        if (data_len >= 0): 
            new_format = HEADER_FMT + str(data_len) + 's'
            values = st.unpack(new_format,bytes)
            self.type = values[0]
            self.cntl = values[1]
            self.seq  = values[2]
            self.ack  = values[3]
            self.size = values[4] 
            self.data = values[5]
            # you dont have to have to implement the the dbg_print function, but its highly recommended 
            dbg_print (1,("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data))))
        else:
            dbg_print (2,("sock352 error: bytes to packet unpacker are too short len %d %d " % (len(bytes), st.calcsize('!bbLLH'))))

        return
    
    # returns a byte array from the Python fields in a packet 
    def pack(self):
        if (self.data == None): 
	    print "NO DATA"
            data_len = 0
        else:
            data_len = len(self.data)
	    print "HAVE DATA"
        if (data_len == 0):
	    print "NO DATA 2"
            bytes = st.pack('!bbLLH',self.type,self.cntl,self.seq,self.ack,self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s' 
            print "NEW FORMAT:",new_format
	    #list_of_outstanding_packets.remove(packet)
	    #print "RETURN?"
        #if(len(list_of_outstanding_packets)==0):	
	    #print "LIST:",list_of_outstanding_packets
	    #print "No more packets outstanding, return"
	    #break
	    #stop_event.set()
	#3print "WHILE(TRUE)"
    #return 
 
def roll(die,sides):  # Define roll function
    r = 0  # Start r at 0 since most people don't know to count 0 as 1, 1 as 2, etc
    while r < die:  # Start While loop to roll based on number of dice selected
        rolls = random.uniform(0,1)  # Store random roll to variable rolls
        r += 1  # Increase r by 1 each loop through until loop validates false
        print("You Rolled a:", rolls)  # Print out the rolls for each die selected
    return rolls

def PacketFound(Packet,address):
    #print "Searching if Packet and address were already successfully sent"
    global list_of_successful_packets
    
    for i in list_of_successful_packets:
        #print "%s Compared to:%s" %(i,(Packet,address))
	if similar(i[0],Packet)==1 and similar(i[1],address)==1:
	    print "Found already successful packet send\n\n\n"
	    return True
    print "Could not find successful packet send... Continue to send delayed packet."	
    return False

# This class holds the data of a packet gets sent over the channel 
# 
class Packet:
    def __init__(self):
        self.type = MESSAGE_TYPE    # ID of sock352 packet
        self.cntl = 0               # control bits/flags 
        self.seq = 0                # sequence number 
        self.ack = 0                # acknowledgement number 
        self.size = 0               # size of the data payload 
        self.data = b''             # data 

    # unpack a binary byte array into the Python fields of the packet 
    def unpack(self,bytes):
        # check that the data length is at least the size of a packet header 
        data_len = (len(bytes) - st.calcsize('!bbLLH'))
        if (data_len >= 0): 
            new_format = HEADER_FMT + str(data_len) + 's'
            values = st.unpack(new_format,bytes)
            self.type = values[0]
            self.cntl = values[1]
            self.seq  = values[2]
            self.ack  = values[3]
            self.size = values[4] 
            self.data = values[5]
            # you dont have to have to implement the the dbg_print function, but its highly recommended 
            dbg_print (1,("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data))))
        else:
            dbg_print (2,("sock352 error: bytes to packet unpacker are too short len %d %d " % (len(bytes), st.calcsize('!bbLLH'))))

        return
    
    # returns a byte array from the Python fields in a packet 
    def pack(self):
        if (self.data == None): 
	    print "NO DATA"
            data_len = 0
        else:
            data_len = len(self.data)
	    print "HAVE DATA"
        if (data_len == 0):
	    print "NO DATA 2"
            bytes = st.pack('!bbLLH',self.type,self.cntl,self.seq,self.ack,self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s' 
            print "NEW FORMAT:",new_format
	    dbg_print(5,("cs352 pack: %d %d %d %d %d %s " % (self.type,self.cntl,self.seq,self.ack,self.size,self.data)))
            PrintPack(self)
	    bytes = st.pack(new_format,self.type,int(self.cntl),self.seq,self.ack,self.size,self.data)
        print "BYTES MADE:",bytes
	return bytes
    
    # this converts the fields in the packet into hexadecimal numbers 
    def toHexFields(self):
        if (self.data == None):
            retstr=  (r'type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x' % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= (r'type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s' % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
	return retstr

    # this converts the whole packet into a single hexidecimal byte string (one hex digit per byte)
    def toHex(self):
        if (self.data == None):
            retstr=  ("%x%x%x%xx%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("%x%x%x%x%xx%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr


# the main socket class
# you must fill in all the methods
# it must work against the class client and servers
# with various drop rates


class Socket:

    def __init__(self):
        # ... your code here ... 
        self.sockett=ip.socket(ip.AF_INET,ip.SOCK_DGRAM)
	#pass 

    # Print a debugging statement line
    # 
    # 0 == no debugging, greater numbers are more detail.
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_debug_level(self, level):
        self.debug_level = level
	return level
    # Set the % likelihood to drop a packet
    #
    # you do not need to implement the body of this method,
    # but it must be in the library,
    def set_drop_prob(self, probability):
	drop_prob = probability
	return probability
    # Set the seed for the random number generator to get
    # a consistent set of random numbers
    # 
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_random_seed(self, seed):
        self.random_seed = seed 
	return seed

    # bind the address to a port
    # You must implement this method
    #
    def bind(self,address):
        # ... your code here ...
        return self.sockett.bind(address) 

    # connect to a remote port
    # You must implement this method
    def connect(self,address):
        return self.sockett.connect(address)
        #pass 


    #accept a connection
    def accept(self):
        # ... your code here ...
        return self.sockett.accept()
    # send a message up to MAX_DATA
    # You must implement this method     
    def sendto(self,buffer,address,State,Server,Repeat):
        # ... your code here ...
        global list_of_outstanding_packets
	global list_of_successful_packets
        
	global RTT
	global MULTIPLIER
	global THRESHOLD
	global TCOUNT
	global RTT_TIMES
        global drop_prob
        #NEEDED FOR THREADS
        global SYN
	global SYNC
	global SYNC2
        global ACK
        global DATA
        global FIN

	P=Packet()
	# Buffer can be recv data directly
	#ParsePack(buffer[0],P)

	#print "P HEX:",P.toHexFields()

	#print "P FIELDS:",PrintPack(P)

	print "\nSTATE:\n",State
	if Server:
	    print "SERVER SEND"
	    if State==STATE_LISTEN:
	        #SEND BACK TO CLIENT INIT MODE
		Q = Packet()
		if(Repeat==False):
		    #ACK=0
		    ParsePack(buffer,P)
		    ParsePack(buffer,Q)
		else:
                    #print "RESEND PACKET P:",PrintPack(P)
		    ParsePack(buffer,Q)
		    #print "RESEND PACKET COPY OF P Q:",PrintPack(Q)
		    P=Q
		    #BECAUSE COULD BE IF OR ELSE...
		#print "Server init back to client final:",PrintPack(P)
		
	        ########	
		ACK=P.seq
		SYN = P.seq
		########
		#zero_stamp1 = time.clock
		R1 = 0

		while(PacketFound(P.toHexFields(),address)==False):
		    start_stamp=time.clock()
		    #Prob = random.uniform(0,1)
		    #print "DROP PROB:",Prob

                    #if(Prob>drop_prob or drop_prob==0):
                    S1 = self.sockett.sendto(str(P.toHexFields()),(address[0],address[1]))
		    print " ",P.toHexFields()
		  
		    try:	
		       	R1 = self.recvfrom(MAX_PKT,0)
		    except:
			print "ERR TIMEDOUT:",R1
			continue


		    end_stamp = time.clock()
		    lapsed_seconds = float(end_stamp - start_stamp) 
		    RTT_TIMES.append(lapsed_seconds)


		    #print "Lapsed seconds:",lapsed_seconds		

		    if(R1!=0): 
                        ParsePack(R1[0],P)
             	    else:
			print "No Parse, will resend..."
			#continue

		    #print "Received",P.toHexFields()

		    RTT = float(sum(RTT_TIMES)) / float(len(RTT_TIMES))
                    #print "MOVING AVERAGE: %.4f Milisecs" % (RTT*1000)
                    #print "AVG GENERAL:%f " % (RTT)

                    #New P ack = old P seq
                    if P.ack==ACK:
                        print "FOUND ACK!"
                        #list_of_successful_packets.append((str(P.toHexFields()),address))
                        MULTIPLIER=1
			break
                    else:
                        print "PACKET NOT FOUND, RETRY INIT"
                        #if(MULTIPLIER*2<=THRESHOLD):
		 	    #MULTIPLIER = MULTIPLIER*2
			#RTT=RTT*MULTIPLIER
			#StartTimeout(Q.toHexFields(),address,RTT,State,True)
			#break
	        
		ACK=2
		#SYN=1

	        #print "PACK111:",PrintPack(P)
	    
		Try = False

		R2=0
		while(Try==False):

		    try:
			Try=True
		        R2 = self.recvfrom(MAX_PKT,RTT)
   	            except:
			Try=False
			print "ERR TIMEOUT"	

	            if(R2!=0):
		        ParsePack(R2[0],P)

		#print "Received",P.toHexFields()

	        #print "PACK222:",PrintPack(P)
		#Made it after second recv...
		##########
		#SYNC = SYNC+1
		IncrSYNC()
		DATA = P.data
		##########
		#print "SERVER's SYN:",SYN
		#print "SERVER's ACK:",ACK
		#print "CLIENT's SYN:",SYNC
	        return self.sendto(P.toHexFields(),address,STATE_SYNRECV,True,False)

	    if State==STATE_SYNRECV:
	    #Server sends back data to client
	        #ACK=0
		print "\n\n\nSERVER ACKNOWLEDGES DATA"
	        Dat = '' 
		
		#print "SERVER's SYN:",SYN
                #print "CLIENT's SYN;",SYNC	

		#print "CLIENT's SYN FIX:",SYNC2	
		
		if(Repeat==False):
		    ParsePack(buffer,P)
		    Dat = P.data
	            SetSock(P,STATE_SYNRECV,'',True)
		else:
		    print "RESEND PACKET, IMPOSSIBLE"		
		    exit(-1)
	        #No need to wait##########################################3 
	        #print "SERVER WILL SEND DATA ACK:",PrintPack(P)

	        ##############
	        ACK=P.ack
	        ##############

		end_stamp = time.clock()
		
		#time.sleep(3)
    
		#D = P.toHexFields()

		#SetSock(P,6,Dat,True)

	        ###############################################################################################
		#print " ",P.toHexFields()
		
		S1 = self.sockett.sendto(P.toHexFields(),(address[0],address[1]))
		#print "S1:,",S1
		#wait(RTT)
		#time.sleep(RTT)
		SetSock(P,6,Dat,True)
		#time.sleep(RTT)
		#print "Send",P.toHexFields()
		S2 = self.sockett.sendto(P.toHexFields(),(address[0],address[1]))
################################################################################################################SWITHCED BECAUSE IT SEND THEM BACKWARDS
		D = Packet()
		
		while(1):
		    try:
		        R1 = self.recvfrom(MAX_PKT,RTT)
		    except:
		        break
		    ParsePack(R1[0],D)
		    #PrintPack(D)
		    if D.seq == SYNC+1:
			print "\n\nFOUND FINAL DATA ACK FROM CLIENT\n\n"
		        break
		    else:
	                print "MISMATCH: D SEQ:%d D CNTL:%d SYN:%d" %(D.seq,D.cntl, SYNC)
	    #while(1):
	        #Prob = random.uniform(0,1)
                #if(Prob>drop_prob or drop_prob==0):
                    #S1 = self.sockett.sendto(str(P.toHexFields()),(address[0],address[1]))
                #R1 = self.recvfrom(MAX_PKT,None)
                #try:
                    #ParsePack(R1[0],P)
                #except:
                    #print "ERR TIMEDOUT:",R1

                #New P ack = old P seq
                #if P.ack==ACK:
                    #print "FOUND ACK!"
                    #list_of_successful_packets.append((str(P.toHexFields()),address))
                    
		    #break
                #else:
                    #print "PACKET NOT FOUND, RETRY INIT"
                    #StartTimeout(P.toHexFields(),address)
	        #    ACK USED FOR SEQ CONFIRM
		SYN=SYN+1
	        return Dat
	    if State == STATE_ESTABLISHED:
                print "SERVER EST... Send all data"
                #Client Established send... Sending all data
		if(Repeat==False):
		    ParsePack(buffer,P)
		    SetSock(P,5,DATA,True)
		else:
		    ParsePack(buffer,P)

                #print "SERVER's SYN:",SYN
                #print "CLIENT's SYN;",SYNC

		
		while(1):
		   
                    RECV = 0
 
		    try:
		        RECV = self.recvfrom(MAX_SIZE,RTT)
		    except:
		        print "ERR TIMEOUT"
    		       		    
		    #print "Receive:",RECV

    		    if(RECV!=0):
 		        ParsePack(RECV[0],P)
		  
		    #print "RECV PACK:",PrintPack(P)
    		    
		    print "P SEQ:%d SYNC:%d"% (P.seq, SYNC)	   
	 
		    if P.seq == SYNC+1:
		        #print "Found correct sync..."
		        #IncrSYNC()
			break
		    else:
			print "Wrong SYNC, wait..."
			#StartTimeout(P.toHexFields(),address)
			
		#print "Received:",P.toHexFields()
	
		#print "PACK FROM CLI:",PrintPack(P)
		#print "SERVER's SYN:",SYN
		#print "CLIENT's SYN;",SYNC
	
		SYNC2 = SYNC
	
		DATA = P.data

		#try: 
		    #self.recvfrom(MAX_SIZE,0.5)
		#except:
		    #print "WAITED 0.5"
		

		return self.sendto(P.toHexFields(),address,STATE_SYNRECV,True,False)
	
	else:
	    print "\n\n\nCLIENT SEND"
	    if State==STATE_INIT:
		#Buffer is empty
		if(Repeat==False):
		    SetSock(P,1,'',False)
	        else:
                    #print "RESEND PACKET"
		    ParsePack(buffer,P)
		    #exit(0)

		#print "INIT PACKET:",PrintPack(P)    
		ACK = P.seq
		while(PacketFound(P.toHexFields(),address)==False):
		    start_stamp=time.clock()	
	            Prob = random.uniform(0,1)
		    #if(Prob>drop_prob or drop_prob==0):
		    S1 = self.sockett.sendto(str(P.toHexFields()),(address[0],address[1]))
		    
		    #print " ",P.toHexFields()

		    R1 = 0
                    try:
                        R1 = self.recvfrom(MAX_PKT,0)
                    except:
                        #print "ERR TIMEDOUT:",R1
			continue
                
		    #print "Received:",P.toHexFields()
	    
                    end_stamp = time.clock()
                    lapsed_seconds = float(end_stamp - start_stamp)
                    RTT_TIMES.append(lapsed_seconds)


                    #print "Lapsed seconds:",lapsed_seconds		  
		    
                    if(R1!=0):
                        ParsePack(R1[0],P)
                    else:
                        print "No Parse, will resend..."
		        #continue

                    RTT = float(sum(RTT_TIMES)) / float(len(RTT_TIMES))
                    print "MOVING AVERAGE: %.4f Milisecs" % (RTT*1000)
                    print "AVG GENERAL:%f " % (RTT)

		    #New P ack = old P seq
		    if P.ack==ACK:
                        #print "FOUND"
                        #list_of_successful_packets.append((str(P.toHexFields()),address))
                        MULTIPLIER = 1
			break
                    else:
			if(MULTIPLIER*2<=THRESHOLD):
			    MULTIPLIER = MULTIPLIER*2
                        RTT=RTT*MULTIPLIER
                        #print "PACKET NOT FOUND, RETRY INIT"
                        #StartTimeout(P.toHexFields(),address,RTT,State,False)
			#break
		
		#####################
		ACK = P.ack
		SYN = P.seq
		#####################
	 	
		#print "RECEIVED:",P.toHexFields()
		#print "",PrintPack(P)
		print "TIME AVG:",RTT
		return self.sendto(P.toHexFields(),address,STATE_SYNSENT,False,False)
	   #REMEMBER FOR LAST LINE OF DATA TRANSFER, SET P ACK TO P SEQ LIKE NORMAL... 
	    if State==STATE_SYNSENT:
	        #SEND BLANK
		Data = ''
		DATA = str(DATA)
		#print "DATA:",DATA
		if(Repeat==False):
		    ParsePack(buffer,P)
		    #P.data=DATA
		    #Data = 
		    SetSock(P,2,'',False)
		    #P.size=len(str(DATA))
		else:
                    #print "RESEND PACKET"
		    ParsePack(buffer,P)
		    #print "RESEND PACKET:",PrintPack(P)
		    exit(0)

		#If P cntl == 3, CONNECTION STAGE... continue with this, initialize stage, else, just set new p ack to old p seq$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ VERY IMPORTANT!!!
		#else: DATA TRANSFER STAGE
		########
		P.ack=SYN
		#Client SYNC
		
		########
		#print "SEND SYN (DUMMY PACK)  TO SERVER:",PrintPack(P)
		

		Q = Packet()
	
		First = False
		Second = False

		#S = Packet()
		#ParsePack(P.toHexFields(),S)
		#THRESHOLD = RTT
		while(First==False or Second == False):
		    start_stamp=time.clock()
                    #Prob = random.uniform(0,1)
                    #if(Prob>drop_prob or drop_prob==0):
                    S1 = self.sockett.sendto(str(P.toHexFields()),(address[0],address[1]))
		    #print " ",P.toHexFields()

		    SetSock(P,4,DATA,False)
		    P.seq=ACK+1	  		    
		    #print "SYN DATA PACKET:",PrintPack(P)
		    

		    ###########
		    SEQ=P.seq
		    #SERVER SYNC
		    SYNC=P.seq
		    ##########

		    
		    #Prob = random.uniform(0,1)
                    #if(Prob>drop_prob or drop_prob==0):
                    #SEQ=P.seq
		    S2 = self.sockett.sendto(str(P.toHexFields()),(address[0],address[1]))
		    #print "Send:",P.toHexFields()
                    
		    R1 = 0
                    
                    try:
                        R1 = self.recvfrom(MAX_PKT,0)
                    except:
                        print "ERR TIMEDOUT:",R1
			continue
		    #print "Receive:",P.toHexFields()

                    end_stamp = time.clock()
                    lapsed_seconds = float(end_stamp - start_stamp)
                    RTT_TIMES.append(lapsed_seconds)

		    #print "Lapsed seconds:",lapsed_seconds

                    if(R1!=0):
                        ParsePack(R1[0],P)
                    else:
                        print "No Parse, will resend..."
			#continue

                    RTT = float(sum(RTT_TIMES)) / float(len(RTT_TIMES))
                    print "MOVING AVERAGE: %.4f Milisecs" % (RTT*1000)
                    print "AVG GENERAL:%f " % (RTT)


		    #print "PACK SYN RECVED BACK:",PrintPack(P) 
                    #New P ack = old P seq
                    if P.ack==SEQ:
                        #print "\n\nFOUNDDDDDDDDDDDDDDDDDDDDdd"
                        #list_of_successful_packets.append((str(P.toHexFields()),address))
                        #SYNC2 = int(P.ack)
			MULTIPLIER=1
			First=True
			Second=True
                    else:
                        #print "PACKET NOT FOUND, RETRY SYNRECV"
			#continue
			if(MULTIPLIER*2<=THRESHOLD): 
			    MULTIPLIER = MULTIPLIER*2
                        RTT=RTT*MULTIPLIER
			#StartTimeout(P.toHexFields(),address,RTT,State,False)
			#break
		
		#print "\n\n\n SYNSENT SYNCH:",SYN
		SYNC2 = P.ack
	 	#R2 = self.recvfrom(MAX_PKT,None)
		#No need to wait################################
		#print "Received DATA ACK FROM SERVER:",R2

		return SYN

	    if State == STATE_ESTABLISHED:
		print "Client EST... Send all data"
	        #Client Established send... Sending all data
		if(Repeat==False):
		    ParsePack(buffer,P)
		    #if P.data !=0:
		        #SYNC += int(P.data)
		    SetSock(P,5,DATA,False)
		else:
		    Q = Packet()
		    ParsePack(buffer,P)
		#if PacketFound(P.toHexFields(),address) or P.seq<SYN:
		    #print "DUPE"
		    #RemoveAll(P.toHexFields(),address)
		    #return
                    #SetSock(P,5,DATA,False)
		    #print "Packet RESEND:",PrintPack(P)
		    #Used to stop infinite looping of threads...
		    #exit(0)
		    #if(len(list_of_outstanding_packets)==0):
		        #exit(0)
		#print "PACK CLI EST:",PrintPack(P)
		#print "BASE RTT:",RTT
		ACK = P.seq
		if RTT==0:
		    RTT = 0.01
		else:
		    THRESHOLD = RTT
		    RTT = RTT/4
		#THRESHOLD = RTT*2
		#RTT = RTT/3
		#THRESHOLD = RTT*2
		#else:
		    #THRESHOLD = RTT
		    #RTT = RTT/2
		S = Packet()
		#ParsePack(P.toHexFields(),S)

		#S = Packet()
		
		#S = P.toHexFields()

		RECV=0
		E=Packet()
		S = Packet()
		T = Packet()
		ParsePack(P.toHexFields(),S)
		while(1):
		    if RTT>=THRESHOLD:
		        MULTIPLIER=1
			RTT=0.1
		    #print "\n\n\n\n\n\n\nRTT:",RTT
		    start_stamp=time.clock()
		    Prob = random.uniform(0,1)
                    #print "Probability:",Prob
		    if(Prob>drop_prob or drop_prob==0):
                        S1 = self.sockett.sendto(P.toHexFields(),(address[0],address[1]))
		    #print "Send:",PrintPack(P)

		    R1 = 0
                    
                    try:
                        R1 = self.recvfrom(MAX_PKT,RTT)
                    except:
                        print "ERR TIMEDOUT:",R1
			MULTIPLIER = MULTIPLIER * 2
                        RTT = RTT * MULTIPLIER
			continue 
		    #print "Receive:",P.toHexFields()
		    #print "FIRST ACK FROM SERV:",R1
		    ParsePack(P.toHexFields(),T)
		    #print "SAVE PACK:",PrintPack(T)
		    ParsePack(R1[0],P)
		
		    print  "EST RECV:", PrintPack(P)

                    end_stamp = time.clock()
                    lapsed_seconds = float(end_stamp - start_stamp)
                    RTT_TIMES.append(lapsed_seconds)

		    #RTT=RTT*2

                    #print "Lapsed seconds:",lapsed_seconds
		    CONT = False
		    Tries = 0 
		    SWT = False
		    while( not CONT ):
			if RTT>=THRESHOLD:
                            MULTIPLIER=1
                            RTT=0.1
			RECV = 0
			try:
	  	            RECV=self.recvfrom(MAX_PKT,RTT)
			except:
                            print "ERR TIMEDOUT 2:",RECV
                            MULTIPLIER = MULTIPLIER * 2
                            RTT = RTT * MULTIPLIER
                            Tries  = Tries+1
			    if Tries >=2:
			        CONT=True
				ParsePack(S.toHexFields(),P)
			    continue

			#E = Packet()
			ParsePack(RECV[0],E)
			#print "Receive:",E.toHexFields()

			#if E.cntl == 2 and P.cntl ==4:
			    #G = Packet()
			    #ParsePack(E.toHexFields(),G)
			    #ParsePack(P.toHexFields(),E)
			    #ParsePack(G.toHexFields(),P)
			#PrintPack(E)
			#print "SYN AND SEQ:",SYN,E.seq
			#SWT = False
			if( E.seq == SYN+1):
			    #print "FOUND SERV SEQRECV"
			    #exit(0)
			    ParsePack(E.toHexFields(),S)
			    break
			else:
			    #print "DID NOT FIND SERV SEQRECV"
			    if E.ack==ACK and P.seq==SYN+1:
				#print "\n\n\n SYNCHECK + 1: %d P SEQ:%d" %(SYN+1,P.seq)
			        SWT = True
				ParsePack(P.toHexFields(),S)
			        ParsePack(E.toHexFields(),P)
				#print "BUT FOUND"
				break
			    continue
		

		    #print "\n\n\n\n\nRECV SERVER SYNREC:",RECV

		    if(R1!=0 and P.ack!=ACK):
                        ParsePack(R1[0],P)
             


                    RTT = float(sum(RTT_TIMES)) / float(len(RTT_TIMES))
                    print "MOVING AVERAGE: %.4f Milisecs" % (RTT*1000)
                    print "AVG GENERAL:%f " % (RTT)

		    
		    #print "PACK RECV:",R1
		    #print "PACK DATA:",PrintPack(P)
		    #print "P ACK and ACK:",P.ack,ACK
		    #exit(0)
		    if ACK==P.ack:
		        #print "FOUND DATA ACK"
			#if SWT==True:
			#list_of_successful_packets.append((str(T.toHexFields()),address))		
			list_of_successful_packets.append((str(S.toHexFields()),address)) 
			list_of_successful_packets.append((str(P.toHexFields()),address))
			#list_of_successful_packets.append((str(E.toHexFields()),address))
		        MULTIPLIER=1
			break
		    else:
			#print "\n\n\n\n\n\n\n\nFAILED TO FIND DATA ACK"
			if(MULTIPLIER*2<=THRESHOLD):
			    MULTIPLIER = MULTIPLIER*2
			else:
			    MULTIPLIER = 1
			    RTT = 0.1
                        RTT=RTT*MULTIPLIER
			TCOUNT=TCOUNT+1
			if TCOUNT>=3:
			    #THRESHOLD = THRESHOLD*2
			    TCOUNT = 0
			#if SWT==True:
		        StartTimeout(T.toHexFields(),address,RTT,State,False)			


		#try:
		    #self.recvfrom(MAX_PKT,2)
		#except:
		    #print ""

		#3time.sleep(0.5)	
		#ParsePack(S.toHexFields(),P)
		print "SEND FINAL ACK DATA TO SERVER..."	
		SetSock(P,S,'',False)
		#.cntl=2	
		self.sockett.sendto(S.toHexFields(),(address[0],address[1]))

		#list_of_successful_packets = []
		list_of_outstanding_packets = []
		
		return R1	    
		if State == STATE_CLOSING:
		    if Repeat==False:
			ParsePack(buffer,P)
		    else:
			print "REPEAT CLI -> SERV STATE CLOSE"
		if RTT==0:
                    RTT = 0.01
                else:
                    THRESHOLD = RTT*2
                    RTT = RTT/2
		while(1):
		    start_stamp = time.clock()
		    print "\n\n\n\n\n\n\nRTT:",RTT
                    start_stamp=time.clock()
                    Prob = random.uniform(0,1)
                    print "Probability:",Prob
                    if(Prob>drop_prob or drop_prob==0):
                        S1 = self.sockett.sendto(P.toHexFields(),(address[0],address[1]))

                    R1 = 0

                    try:
                        R1 = self.recvfrom(MAX_PKT,RTT)
                    except:
                        print "ERR TIMEDOUT:",R1
                        MULTIPLIER = MULTIPLIER * 2
                        RTT = RTT * MULTIPLIER
                        continue

     		    end_stamp = time.clock()
                    lapsed_seconds = float(end_stamp - start_stamp)
                    RTT_TIMES.append(lapsed_seconds)

                    #RTT=RTT*2

                    print "Lapsed seconds:",lapsed_seconds

                    if(R1!=0):
                        ParsePack(R1[0],P)
                    else:
                        print "No Parse, will resend..."
                        #continue


		

    # receive a message up to MAX_DATA
    # You must implement this method     
    def recvfrom(self,nbytes,Timeout):
	print("\nRECEIVING...\n")
	if Timeout==0:
	    RTT=None
	else:
	    RTT=Timeout
	self.sockett.settimeout(RTT)
        
	return self.sockett.recvfrom(nbytes)
    # close the socket and make sure all outstanding
    # data is delivered 
    # You must implement this method         
    def close(self):
        # ... your code here ...
        return self.sockett.close()

def StartTimeout(Packet,dest_addr,Time,State,Server): 
    # Packet, destination, avg time, State, Server or not       
    # Example how to start a start the timeout thread
    global sock352_dbg_level
    global list_of_outstanding_packets 
    
    sock352_dbg_level = sock352_dbg_level + 1
    #T = time.clock()
    if((Packet) not in list_of_outstanding_packets and (Packet) not in  list_of_successful_packets ):
        list_of_outstanding_packets.append((Packet,dest_addr,time.clock(),State,Server))
    else:
	print "No repeated packets for thread..."
	return None 
    dbg_print(3,"starting timeout thread")

    # create the thread 
    #Time DELEY can be sed with an offset.. later!
    thread1 = sock352Thread(1, "Thread-1", Time)

    # you must make it a daemon thread so that the thread will
    # exit when the main thread does. 
    thread1.daemon = True

    # run the thread 
    thread1.start()
    return thread1

__author__ = 'edgar'

#import dpkt
from sys import argv
from subprocess import call
from scapy.all import *
import time
import re
import os
import struct
import threading
import binascii
import csv


script, filename = argv;

class DataContainer:


    def __init__(self):

        #self.FIRSTSEQNUM = 802159925;
        self.FIRSTSEQNUM = -9999;
        self.seqNum = 0;
        self.totPkts = 0;
        self.totPktsReceived = 0; # Total packets received
        self.totPktsLost = 0;
        self.totBitErrs = 0; # Total bit errors
        self.pktLoss = 0; # Packet loss rate
        self.bitErr = 0; # Bit error rate
        self.appxErr = 0; # Appx error rate
        #self.errPos; # Array for bitwise op to find error pos
        #self.currPkt; # Current packet being analyses

    # Get number of packets lost from second last received seq num and last seq num received
    def getPktLoss(self, prevSQ, newSQ):
        if (newSQ - prevSQ) > 1:
            self.totPktsLost += (newSQ-prevSQ)-1;
        self.totPkts = newSQ - self.totPktsLost; # newSeq represents # packets sent so far

    def printInfo(self):
        os.system('clear');

        print( "Total packets sent: %d\n" % self.totPkts );
        print( "Number of successful packets: %d\n" % self.totPktsReceived );
        print( "Number of corrupted packets: %d\n" % self.totPktsLost );

        print( "Packet loss rate: %d%%\n" % (self.pktLoss*100) );

        print( "Total bit errors: %d\n" % self.totBitErrs );
        #print( "Bit error rate: %d%%\n" % self.bitErr*100 );

    def fillPktInfo(self, tpl):
        # if statement so that first seq number is counted; otherwise will produce error.
        if tpl[0] != self.FIRSTSEQNUM:
            self.totPkts = (tpl[0] + tpl[1]) - self.FIRSTSEQNUM; # Latest sequence number
        else:
            self.totPkts = tpl[1];


        self.totPktsReceived += tpl[1];
        self.totPktsLost = self.totPkts - self.totPktsReceived;

        try:
            self.pktLoss = self.totPktsLost/self.totPkts;
        except ZeroDivisionError:
            self.pktLoss = self.pktLoss;

    def fillPktInfo_8091(self, tpl):

        # Used to record very first sequence number of trial. This is needed to calculate
        # total number of packets sent thus far.
        if self.FIRSTSEQNUM == -9999:
            self.FIRSTSEQNUM = tpl[0][0];

        # Get total of packets sent thus far by comparing initial sequence number and
        # latest batch of good packets processed.
        v = tpl[len(tpl)-1];
        self.totPkts = v[0]+v[1] - self.FIRSTSEQNUM + 1;

        # Calculate total of good packets sent thus for for the trial
        for i in tpl:
            self.totPktsReceived += i[1];

        # Calculate number bad packets
        self.totPktsLost = self.totPkts - self.totPktsReceived;

        # Calculate packet loss rate
        try:
            self.pktLoss = round(float(self.totPktsLost)/float(self.totPkts)*float(100),2);
        except ZeroDivisionError:
            pass;


    def fillPktInfo_8092(self, ls):
        self.totBitErrs += ls[0];

        self.bitErr = float(self.totBitErrs)/float(self.totPkts*float(996)*float(8)); # bit errors/total bits

    # Write the state of the data to csv file
    def writeToFile(self, filename):
        file = open(filename, 'w');
        writer = csv.writer(file);

        data = [['TotPkts', self.totPkts],\
                ['TotPktsReceived', self.totPktsReceived],\
                ['TotPktsLost', self.totPktsLost],\
                ['PktLostRate', self.pktLoss],\
                ['BitErrors', self.totBitErrs],\
                ['BitErrorRate', self.bitErr]];

        writer.writerows(data);
        file.close();


def prbs9(state = 0x1ff):
    while True:
        for i in range(8):
            if bool(state & 0x10) ^ bool(state & 0x100):
                state = ((state & 0xff) << 1) | 1
            else:
                state = (state & 0xff) << 1
        yield state & 0xff


def parse_packet(pkt):
    if hasattr(pkt, 'data'):
        npkt = pkt.data;
    lst = [];
    i = 0;
    for i in range(0, len(npkt)-7, 8):
        v = struct.unpack('>LL', npkt[i:i+8]);
        if v[1] > 0:
            lst.append(v);
        return lst;

def get_num_bit_errors(hexword):
    switcher = {
        '0': 0,
        '1': 1,
        '2': 1,
        '3': 2,
        '4': 1,
        '5': 2,
        '6': 2,
        '7': 3,
        '8': 1,
        '9': 2,
        'a': 2,
        'b': 3,
        'c': 2,
        'd': 3,
        'e': 3,
        'f': 4
    }

    return switcher.get( hexword.lower(), -9999);


# Parse packet from FPGA that has number of good packets received info & returns tuple
# containing this information = ( start sequence, number of packets following sequence )
# Note that these packets are of ethtype 0x8091
def parse_8091_packet(pkt):
    # pkt comes in as byte per hex value

    pktData = str(pkt);
    lst = [];
    #print pkt;
    #print pktData;
    #hexdump(pkt);

    i = 0;

    # Unpack only data section of packet
    for i in range(14, len(pktData)-7, 8):
        #print pktData[i:i+8].encode('hex');
        v = struct.unpack('>LL', pktData[i:i+8]);

        if v[1] > 0:
            lst.append(v);

    return lst;


# Returns array with number of bit errors in packet and 996 byte string that indicated where
# those errors occured.
def parse_8092_packet(pkt):

    gen = prbs9(); # Check packet data against this, bitwise;
    output = [];

    pktinfo = (pkt[0]); # All packet data is contained in first index
    data = str(pktinfo)[18:len(pktinfo)].encode('hex'); #  Grab data section & convert to hex (only get 996 of prbs9)
    #bindata = binascii.unhexlify(data); #Convert to binary <--convert to int?
    #print type(bindata);
    #print type(pktinfo);
    ls = ''
    vals = [];
    numerrs = 0;


    #print data.encode('hex') + '\n';


    #print bindata;
    #print ( (int(bindata)&gen) );

    i=1; # For 996 byte loop
    j=0; # For d_str array movement
    """
    try:
        while True:
            item = next(gen);
            #print item;
            # Do stuff
            #print 'key (per byte): ' + str(item).encode('hex');
            #print 'value (per byte): ' + data[i];

            i += 1;
            print i;
            #output.append( ( int(bindata)&item)|(~int(bindata)&~item) );
    except StopIteration:
        pass
    finally:
        del gen;
    """

    # Check bit errors per byte (up to 996 bytes for prbs9
    for item in gen:

        if i > 996:
            break;

        #key += str(hex(item));
        d_str = data[j] + data[j+1]; # Get each byte as string from data
        d_int = int(d_str,16); # Convert hex string byte to int
        result = item ^ d_int; # xor prbs9 byte data with byte data


        r_hex = hex(result); # Convert result to hex string

        # Append to total number of bit errors
        for a in r_hex[2:len(r_hex)]:
            numerrs += get_num_bit_errors(a.lower());

        ls += ( r_hex[2:len(r_hex)] ); # Append byte hex string to all byte results for packet


        i += 1;
        j += 2;

    #print output;
    #print bindata + '\n';
    #print "key len: " + str(i);
    vals.append(numerrs);
    vals.append(ls);

    return vals;



def get_packet_protocol(pkt):
    pktInfo = str(pkt);

    protocol = pktInfo[12].encode('hex') + pktInfo[13].encode('hex');

    return protocol;



def processPkt (pkt, container):
    # Process part
    # No info :(

    # Display part
    #print( pkt.summary() );
    # print( pkt.show() );
    time.sleep(0.01);
    #hexdump(pkt)

    #if pkt.getLayer(Raw).load is not None:
    #    print( pkt.getlayer(Raw).load );

    # print( str(pkt) ); # Works - Gives  data as string


    """ Good stuff
    pktData = str(pkt); # Convert to string
    strp = re.sub('[^0-9]','',pktData); # Only numerical characters


    # Update stored sequence number
    # Avoid empty string integer conversion error
    if strp != '':
        #print( int(strp) );
        container.seqNum = int(strp);
    #container.seqNum = int( pktData );
    """


    #print parse_packet(pkt);

    etherproto = get_packet_protocol(pkt);

    # Pick respective prosessing methods based on etherprotocol.
    # Also, do not process corrupted packets - packets not of correct byte size.
    if (etherproto == '8091' and len(pkt) == 60):
        info = parse_8091_packet(pkt);

        # Prevent analysis on bad packet
        if info != None:
            container.fillPktInfo(info);

    elif (etherproto == '8092' and len(pkt) == 1014):
        badinfo = parse_8092_packet(pkt);
        container.fillPktInfo_8092(badinfo);




def RunPCAPRead (filename):
    # To start it off
    pkts = rdpcap(filename);
    outpkts = [];
    start = 0;
    end = len(pkts)-1;


    # Create data container class to record information
    metaData = DataContainer();

    while 1:
        while( start <= end ):
            # Do parsing right here....
            #outpkts.append(pkts[start]);
            #print( "Packet: %s" % (pkts[start])[0][1].src);
            # DO SOMETHING
            #(pkts[start])[0][1].show();

            lastSQ = metaData.seqNum;

            # Updates metaData from previous call
            processPkt(pkts[start], metaData);

            #metaData.getPktLoss(lastSQ, metaData.seqNum);




            start += 1; # Required for looping

            # Real time data printing
            metaData.printInfo();



        # Update start & end to include newly generated packets in log file
        pkts = rdpcap(filename); # Open updated
        start = end;
        end = len(pkts)-1;


def RunTrial(numpkts, filename):

    # Construct tshark call string
    interf = "eth8"
    tsharkArgs = " -i " + interf + " -c " + str(numpkts) + " -w " + filename + " -F pcap";

    # Logfile must aleady exist before hand
    os.mknod(filename);

    # Start wireshark and record logfile for n amount of time
    #call(["tshark", tsharkArgs]);
    os.system( "tshark" + tsharkArgs );



    # Open logfile for processing
    pkts = rdpcap(filename);
    metaData = DataContainer();

    for pkt in pkts:
        etherproto = get_packet_protocol(pkt);

        # Pick respective prosessing methods based on etherprotocol.
        # Also, do not process corrupted packets - packets not of correct byte size.
        if (etherproto == '8091' and len(pkt) == 60):
            info = parse_8091_packet(pkt);

            # Prevent analysis on bad packet
            if info != None:
                metaData.fillPktInfo_8091(info);

        elif (etherproto == '8092' and len(pkt) == 1014):
            badinfo = parse_8092_packet(pkt);
            metaData.fillPktInfo_8092(badinfo);


    # Write analysis to file
    fn = filename[:-5]; # Strip .pcap from filename string
    metaData.writeToFile(fn+".csv");


def StartPCAPReadDaemon(logfile):
    readThread = threading.Thread( target=RunPCAPRead, kwargs=dict(filename=logfile) );
    readThread._stop = threading.Event();
    readThread.start();
    time.sleep(1);

#RunPCAPRead(filename);
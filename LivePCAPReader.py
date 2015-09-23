__author__ = 'edgar'

import dpkt
from sys import argv
from scapy.all import *
import time
import re
import os
import struct


script, filename = argv;

class DataContainer:


    def __init__(self):

        self.FIRSTSEQNUM = 802159925;
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


# Parse packet from FPGA that has number of good packets received info & returns tuple
# containing this information = ( start sequence, number of packets following sequence )
def my_parse_packet(pkt):
    # pkt comes in as byte per hex value

    pktData = str(pkt);
    lst = [];
    #print pkt;
    #print pktData;
    #hexdump(pkt);

    i = 0;

    for i in range(14, len(pktData)-7, 8):
        #print pktData[i:i+8].encode('hex');
        v = struct.unpack('>LL', pktData[i:i+8]);

        if v[1] > 0:
            return v;





def processPkt (pkt, container):
    # Process part
    # No info :(

    # Display part
    #print( pkt.summary() );
    # print( pkt.show() );
    time.sleep(0.5);
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

    info =  my_parse_packet(pkt);
    container.fillPktInfo(info);



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



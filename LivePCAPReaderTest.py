__author__ = 'edgar'

import LivePCAPReader as PCAPReader
from sys import argv;
from scapy.all import *
import struct

script, filename = argv;

def gen_8091_pkt():
    SRC='08:11:96:50:3a:1c';
    DST='08:11:96:50:3a:1c';

    # Craft ethernet packet
    pkt = Ether();
    pkt.src=SRC;
    pkt.dst=DST;
    pkt.type=0x8091;


    #data = b'\x00'+b'\x00'+b'\x00'+b'\x01'; # Will hold 996 bytes prbs9 data
    # Start off with the 4 bytes of sequence number

    # Only want 996 bytes of prbs9
    data = bytes();
    data += struct.pack('>LL', 1,3);
    data += struct.pack('>LL', 5,7);
    data += struct.pack('>LL', 99, 2);

    b = pkt/data;


    #print len(b);
    #hexdump(b);
    return b;

def gen_8092_pkt():
    SRC='08:11:96:50:3a:1c';
    DST='08:11:96:50:3a:1c';

    # Craft ethernet packet
    pkt = Ether();
    pkt.src=SRC;
    pkt.dst=DST;
    pkt.type=0x8092;

    # Generate prbs9
    gen = PCAPReader.prbs9()


    data = b'\x00'+b'\x00'+b'\x00'+b'\x01'; # Will hold 996 bytes prbs9 data
    # Start off with the 4 bytes of sequence number

    # Only want 996 bytes of prbs9
    i=1;
    for d in gen:
        if i > 996:
            break;

        data += struct.pack('>B', d);

        i += 1;

    b = pkt/data

    #print len(b);
    #hexdump(b);
    return b;

def gen_bad_8092_pkt():
    SRC='08:11:96:50:3a:1c';
    DST='08:11:96:50:3a:1c';

    # Craft ethernet packet
    pkt = Ether();
    pkt.src=SRC;
    pkt.dst=DST;
    pkt.type=0x8092;


    # Generate prbs9
    gen = PCAPReader.prbs9()


    data = b'\x00'+b'\x00'+b'\x00'+b'\x01'; # Will hold 996 bytes prbs9 data
    # Start off with the 4 bytes of sequence number

    # Only want 996 bytes of prbs9
    i=1;
    for d in gen:
        if i > 996:
            break;

        # Corrupt prbs9
        if (i==15):
            #print hex(d);
            #print hex(42);
            data += struct.pack('>B', 42);
        else:
            data += struct.pack('>B', d);

        i += 1;

    b = pkt/data

    #print len(b);
    #hexdump(b);
    return b;

def main():

    # Test 0x8091 packet processing

    """
    # Test 0x8092 packet processing
    print "Begin 0x8092 Good Test";
    pkt = gen_8092_pkt();

    values = PCAPReader.parse_8092_packet(pkt);

    print "Number of bit errors: " + str(values[0]);
    print "Bit error positions: ", values[1];



    print "Begin 0x8092 Bad Test";
    pkt = gen_bad_8092_pkt();

    values = PCAPReader.parse_8092_packet(pkt);

    print "Number of bit errors: " + str(values[0]);
    print "Bit error positions: ", values[1];



    print "Begin Output to file test";
    dataContainer = PCAPReader.DataContainer();
    dataContainer.fillPktInfo_8091(PCAPReader.parse_8091_packet(gen_8091_pkt()));
    dataContainer.fillPktInfo_8092(PCAPReader.parse_8092_packet(gen_bad_8092_pkt()));
    dataContainer.writeToFile('Iteration1.csv');
    print "Done."
    """

    # Start RunTrial test

    PCAPReader.RunTrial(10000, "Trial1.pcap");



main();
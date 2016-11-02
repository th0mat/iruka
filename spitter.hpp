//
// Created by Thomas Natter on 3/19/16.
//

#ifndef SPITTER_SPITTER_H
#define SPITTER_SPITTER_H


#include <iostream>
#include <vector>
#include <pcap/pcap.h>
#include <map>
#include <chrono>
#include <set>
#include "config.hpp"


struct pcap_file_rec_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};


struct RadioTapHeader {
    // todo: automate the location of channelFreq based on present flags ... currently manual
    u_char version;    // set to 0
    u_char pad;
    u_short length;    // entire length
    uint32_t present;     // fields present
    u_char bytesBeforeChannel[10];  // as per fields present
    u_short channelFreq;
};


struct MacHeader {
    unsigned protocol:2;
    unsigned type:2;
    unsigned subtype:4;
    unsigned toFromDs:2;
    unsigned frags:1;
    unsigned retry:1;
    unsigned pwrMgt:1;
    unsigned moreData:1;
    unsigned wep:1;
    unsigned order:1;
    u_short duration;
    u_char addr1[6];
    u_char addr2[6];
    u_char addr3[6];
};

struct Packet {
    bool crc;
    uint64_t timeStampMicroSecs;  // in microsec unix time
    int32_t lengthInclRadioTap;
    RadioTapHeader* radioTapHeader;
    MacHeader* macHeader;
};


struct StaData {
    int packets;
    int bytes;
    StaData();
};


struct Summary {
    Summary(std::chrono::time_point<std::chrono::system_clock>);
    StaData corrupted;
    StaData valid;  // incl control frames (which are excluded in the STA numbers)
    std::chrono::time_point<std::chrono::system_clock> periodEnd;
    std::map<uint64_t, StaData> stations;
};


struct StationSet {
    StationSet(std::chrono::time_point<std::chrono::system_clock>);
    std::chrono::time_point<std::chrono::system_clock> periodEnd;
    std::map<uint64_t, uint64_t> stations;  // sta, bytes

};

//struct SeenTimes {
//    uint32_t first;
//    uint32_t last;
//    SeenTimes(uint32_t, uint32_t);
//};
//

//std::map<uint64_t, SeenTimes> allStationsEver;


void rawHandler(u_char *args, const pcap_pkthdr *header, const u_char *packet);


int32_t startSpitting();


u_short getRadioTapLength(const u_char*);


void checkPeriods(const pcap_pkthdr*);


void addToSummaryAndSet(const Packet&);


//void addToAllStationsEver(const StationSet&);


void hop();




#endif //SPITTER_SPITTER_H

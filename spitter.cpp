//
// Created by Thomas Natter on 3/20/16.
//

#include <iostream>
#include <vector>
#include <pcap/pcap.h>
#include <ios>
#include <thread>
#include <fstream>
#include <sstream>
#include "crc.hpp"
#include "config.hpp"
#include "spitutils.hpp"
#include "monitor.hpp"


volatile bool keepHopping = true;


bool filterOut(uint64_t);


void packetHandler(const Packet& pkt) {
    if (Config::get().outScrPkts) screenPrintPacket(pkt);
};


void summaryHandler(const scrSummary& summary) {
    if (Config::get().outScrPeriodHdr) screenPrintPeriodHeader(summary);
    if (Config::get().outScrPeriodDetails) screenPrintPeriodDetails(summary);
    if (Config::get().outScrPeriodJSON) screenPrintPeriodJSON(summary);
};


void stationSetHandler(const dbSummary& stationSet) {
    if (Config::get().dbLog) {
        dbLogStationSet(stationSet);
    }
};


uint32_t startTime = time(nullptr);


scrSummary::scrSummary(std::chrono::time_point<std::chrono::system_clock> t_point) :
        periodEnd{t_point} {}


dbSummary::dbSummary(std::chrono::time_point<std::chrono::system_clock> t_point) :
        periodEnd{t_point} {}


scrSummary* currentSummary;
dbSummary* currentStationSet;


StaData::StaData() : packets{0}, bytes{0} {};


/* loop callback function - set in pcap_loop() */
void rawHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet) {
    bool crc = crc32(header, packet);
    uint64_t timeStampMicroSecs = (uint64_t) header->ts.tv_sec * 1000000 + header->ts.tv_usec;
    int lengthInclRadioTap = header->len;
    const MacHeader* const_mac = reinterpret_cast<const MacHeader*>(packet + getRadioTapLength(packet));
    MacHeader* mac = const_cast<MacHeader*>(const_mac);
    const RadioTapHeader* const_radio = reinterpret_cast<const RadioTapHeader*>(packet);
    RadioTapHeader* radio = const_cast<RadioTapHeader*>(const_radio);
    Packet pkt{crc, timeStampMicroSecs, lengthInclRadioTap, radio, mac};
    checkPeriods(header);
    addToSummaries(pkt);
    packetHandler(pkt); // for output of pkt
}


int startSpitting() {
    // add monitor thread in case of dbLogging and open db
    dbCreateTrafficTable();
    std::thread mon;
    if (Config::get().dbLog) mon = std::thread(monitor, startTime);
    // pcap config
    pcap_t* handle;                        // session handle
    char errbuf[PCAP_ERRBUF_SIZE];         // buff for error string
    struct bpf_program fp;                 // compiled filter
    //bpf_u_int32 mask;					   // netmask mask - not set
    bpf_u_int32 net = 0;                   // our IP - needed only as arg
    // pcap_create allows setting params before activation - pacap_open_golive
    // combines those two steps -> setting monitor mode not possible
    // SpitterConfig config;
    handle = pcap_create(Config::get().device.c_str(), errbuf);
    if (handle == NULL) {
        printf("*** pcap_create failed: %s\n", errbuf);
        return (2);
    }
    if (pcap_can_set_rfmon(handle) != 1) std::cout << "*** can't set rfmon\n";
    // set monitor mode
    if (pcap_set_rfmon(handle, 1) != 0) {
        printf("*** pcap_set_rfmon failed");
    }
    // snaplen -1 does not work on rpi
    if (pcap_set_snaplen(handle, -1) != 0) {
        printf("*** pcap_set_snaplen failed");
    };          // -1: full pkt
    if (pcap_set_timeout(handle, 500) != 0) {
        printf("*** pcap_set_timeout failed");
    };         // millisec
    int status = pcap_activate(handle);
    if (status != 0) printf("*** pcap_activate status returned: %d \n", status);
    // check for link layer
    if (pcap_datalink(handle) != 127) {
        printf("*** link layer: %d \n", pcap_datalink(handle));
        printf("*** device %s doesn't exist or provide RadioTap headers\n", Config::get().device.c_str());
        return (2);
    }
    // compile and apply BPF
    if (pcap_compile(handle, &fp, Config::get().bpf.c_str(), 0, net) == -1) {
        printf("*** failed to parse filter %s: %s\n", Config::get().bpf.c_str(), pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("*** failed to install filter %s: %s\n", Config::get().bpf.c_str(), pcap_geterr(handle));
        return (2);
    }
    // start channel hopping
    if (Config::get().hop) {
        std::thread t1(hop);
        t1.detach();
    }
    // initialize
    currentSummary = new scrSummary(std::chrono::time_point<std::chrono::system_clock>() +
                                    std::chrono::seconds(startTime - startTime % Config::get().scrPeriodLength +
                                                         Config::get().scrPeriodLength));

    currentStationSet = new dbSummary(std::chrono::time_point<std::chrono::system_clock>() +
                                      std::chrono::seconds(startTime - startTime % Config::get().dbPeriodLength +
                                                           Config::get().dbPeriodLength));




    // enter loop
    pcap_loop(handle, -1, rawHandler, nullptr);        // -1: no pkt number limit
    pcap_close(handle);
    if (Config::get().hop) {
        keepHopping = false;
        std::this_thread::sleep_for(std::chrono::microseconds(1000000));
    }
    return 0;
}


u_short getRadioTapLength(const u_char* packet) {
    const RadioTapHeader* rth = reinterpret_cast<const RadioTapHeader*>(packet);
    const u_short result = rth->length;
    return result;
}


void checkPeriods(const pcap_pkthdr* header) {
    auto nowTime = std::chrono::time_point<std::chrono::system_clock>() +
                   std::chrono::microseconds(header->ts.tv_usec + (uint64_t) header->ts.tv_sec * 1000000);

    if (nowTime >= currentSummary->periodEnd) {
        summaryHandler(*currentSummary);
        currentSummary->periodEnd = currentSummary->periodEnd + std::chrono::seconds(Config::get().scrPeriodLength);
        currentSummary->stations.clear();
        currentSummary->corrupted = StaData();
        currentSummary->valid = StaData();
    }

    if (nowTime >= currentStationSet->periodEnd) {
        stationSetHandler(*currentStationSet);
        currentStationSet->stations.clear();
        currentStationSet->periodEnd =
                currentStationSet->periodEnd + std::chrono::seconds(Config::get().dbPeriodLength);
    }
}


namespace PktTypes {
    // if type == 00
    //      subtype  0: addr2   // Assoc Request
    //      subtype  1: addr1   // Assoc Resp
    //      subtype  2: addr2   // Reassoc Request
    //      subtype  3: addr1   // Reassoc Response
    //      subtype  4: addr2   // Probe Request
    //      subtype  5: addr1   // Probe Response
    //      subtype  6: ??
    //      subtype  7: ??
    //      subtype  8: addr1   // Beacon
    //      subtype  9: addr1   // ATIM
    //      subtype 10: addr2   // Disassociation
    //      subtype 11: addr2   // Authentication
    //      subtype 12: addr2   // Deauthentication
    //      subtype 13: addr2   // Action??
    //      subtype 14: -       // reserved
    //      subtype 15: -       // reserved  // obsered in the wild with passed crc // at starbucks
    const std::vector<int> t0{2, 1, 2, 1, 2, 1, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0};

    // if type == 01
    // length of CTS and ACK is 14, all others 20 bytes
    //      subtype  0: -         // reserved
    //      subtype  1: -         // reserved
    //      subtype  2: -         // reserved
    //      subtype  3: -         // reserved
    //      subtype  4: -         // reserved
    //      subtype  5: -         // reserved
    //      subtype  6: -         // reserved
    //      subtype  7: -         // reserved
    //      subtype  8: addr1/2   // Block ACK request
    //      subtype  9: addr1/2   // Block ACK
    //      subtype 10: addr1/2   // PS-Poll
    //      subtype 11: addr1/2   // RTS
    //      subtype 12: addr1/2   // CTS
    //      subtype 13: addr1/2   // ACK
    //      subtype 14: addr1/2   // CF End
    //      subttpe 15: addr1/2   // CF End + ACK
    // const std::vector<int> t1{0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 2, 1, 1, 0, 0};

    // if type == 02
    // toFromDs table
    //      toFromDs 0:  addr0
    //      toFromDs 1:  addr1
    //      toFromDs 2:  addr2
    //      toFromDs 3:  addr0
    const std::vector<int> t2{0, 2, 1, 0};
};


uint64_t getStaAddr(const Packet& pkt) {
    int no = 0;
    if (pkt.macHeader->type == 0) { no = PktTypes::t0[pkt.macHeader->subtype]; }
    // if (pkt.macHeader.type == 1) { no = PktTypes::t1[pkt.macHeader.subtype]; } // excluded in addToSummary
    if (pkt.macHeader->type == 2) { no = PktTypes::t2[pkt.macHeader->toFromDs]; }
    if (no == 0) return 666;   // for "undefined";
    if (no == 1) return addressToLong(pkt.macHeader->addr1);
    if (no == 2) return addressToLong(pkt.macHeader->addr2);
    return 666;
}


void addToSummaries(const Packet& pkt) {
    // if corrupted, add to corrupted
    if (!pkt.crc) {
        currentSummary->corrupted.bytes += pkt.lengthInclRadioTap;
        currentSummary->corrupted.packets += 1;
        return;
    }
    currentSummary->valid.bytes += pkt.lengthInclRadioTap;
    currentSummary->valid.packets += 1;
    if (pkt.macHeader->type == 1) return; // exclude control frames from STA identification
    if (pkt.macHeader->type == 2 && pkt.macHeader->toFromDs == 0) return; // exclude data frames not to/from STA
    if (pkt.macHeader->type == 2 && pkt.macHeader->toFromDs == 3) return; // exclude data frames not to/from STA
    uint64_t sta = getStaAddr(pkt);
    if (filterOut(sta)) return;  // broadcast
    // add pkt to currentStationSet
    auto p = currentStationSet->stations.find(sta);
    if (p != currentStationSet->stations.end()) {
        p->second += pkt.lengthInclRadioTap;
    } else {
        uint64_t bytes = pkt.lengthInclRadioTap;
        currentStationSet->stations.insert(std::pair<uint64_t, uint64_t>(sta, bytes));
    }
    // add pkt to currentSummary
    auto ptr = currentSummary->stations.find(sta);
    if (ptr != currentSummary->stations.end()) {
        ptr->second.packets += 1;
        ptr->second.bytes += pkt.lengthInclRadioTap;
    } else {
        StaData data;
        data.bytes = pkt.lengthInclRadioTap;
        data.packets = 1;
        currentSummary->stations[sta] = data;
    }
};


bool filterOut(uint64_t sta) {
    bool out = false;
    if (sta == 281474976710655) out = true; // broadcast
    std::string hex6 = longToHex(sta).substr(0, 6);
    std::string hex4 = longToHex(sta).substr(0, 4);
    if (hex4 == "3333") out = true; // IPv6 multicast
    if (hex6 == "00005e") out = true; // assigned to IANA
    if (hex6 == "01005e") out = true; // assigned to IANA
    if (hex6 == "0180c2") out = true; // spanning trees for bridges
    return out;
}


void hop() {
    Config config = Config::get();
    std::system("sudo /bin/bash -c 'airport en0 -z'");
    int c;
    int remain = 1000000 / config.hopsPerSec;
    std::string cmd_base = "sudo /bin/bash -c 'airport en0 -c";
    std::string cmd;
    while (keepHopping) {
        c = config.channels[std::rand() % config.channels.size()];
        cmd = cmd_base + std::to_string(c) + "'";
        std::system(cmd.c_str());
        std::this_thread::sleep_for(std::chrono::microseconds(remain));
    }
    std::system("sudo /bin/bash -c 'ifconfig en0 up'");
    std::cout << "[*] channel hopping terminated\n";
    return;
}

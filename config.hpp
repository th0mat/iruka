//
// Created by Thomas Natter on 3/3/16.
//

#ifndef PCAP_CONFIG_H
#define PCAP_CONFIG_H

#include <iostream>
#include <vector>



class Config{

private:
    Config();

public:

    // sniffer
    std::string device;
    std::string bpf;

    // db
    int32_t dbPeriodLength;  // for filing in txt db
    std::string dbDir;
    std::string allStationsEver;
    bool dbLog;

    // display
    int32_t scrPeriodLength;  // for display of traffic information
    bool outScrPkts;
    bool outScrPeriodHdr;
    bool outScrPeriodDetails;
    bool outScrPeriodJSON;

    // hopper
    bool hop;
    int32_t hopsPerSec;
    std::vector<u_short> channels;

    static Config& get();
};


#endif //PCAP_CONFIG_H

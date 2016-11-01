//
// Created by Thomas Natter on 3/14/16.
//

#include "config.hpp"

Config::Config() {

    // sniffer
    device = "en0";
    bpf = "wlan[0] & 3 == 0 and (not wlan type control) and (not subtype beacon)";

    // display
    scrPeriodLength = 60;
    outScrPkts = false;
    outScrPeriodHdr = false;
    outScrPeriodDetails = false;
    outScrPeriodJSON = true;

    // db
    dbPeriodLength = 60;
    allMacKeepDays = 3;
    dbLog = true;
    dbDir = "iruka.data";
    allStationsEver = "allStations.log";

    // hopper
    hopsPerSec = 0;
    hop = false;
    channels = {1, 3, 5, 7, 9, 11};
}



Config& Config::get() {
    static Config* config = new Config();
    return *config;
}


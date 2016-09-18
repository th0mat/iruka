//
// Created by Thomas Natter on 3/23/16.
//

#include <fstream>
#include <sstream>
#include <iomanip>
#include <set>
#include <ctime>
#include <cstring>
#include "spitter.hpp"
#include "spitutils.hpp"
#include "config.hpp"

using std::chrono::microseconds;
using std::chrono::seconds;
using std::chrono::system_clock;
typedef std::chrono::time_point<system_clock> t_point;


void getAddresses(const Packet& pkt, int macPktLength, std::string& addr1, std::string& addr2, std::string& addr3);


uint64_t addressToLong(const u_char* p) {
    u_char tmp[8]{};
    // leave tmp[6] and tmp[7] = 0;
    for (int i = 0; i < 6; i++) {
        tmp[5 - i] = p[i];
    }
    return *(reinterpret_cast<uint64_t*>(&tmp));
}


std::string longToHex(const uint64_t& mac64) {
    std::stringstream stream;
    stream << std::setfill('0') << std::setw(12) << std::hex << mac64;
    return stream.str();
}


void screenPrintPeriodDetails(const Summary& summary) {
    char timeStamp[100];
    time_t tt = std::chrono::duration_cast<seconds>(summary.periodEnd.time_since_epoch()).count();
    std::strftime(timeStamp, sizeof(timeStamp), "%Y-%m-%d %H:%M.%S", std::localtime(&tt));
    for (auto ptr = summary.stations.begin(); ptr != summary.stations.end(); ptr++) {
        printf("%s ----  %-20s  KB/s: %8.2f\n",
               timeStamp,
               longToHex(ptr->first).c_str(),
               ptr->second.bytes / 1024.0 / Config::get().scrPeriodLength
        );
    }
    std::cout << "\n";
}


void screenPrintPeriodJSON(const Summary& summary) {
    std::string json = "{ ";
    for (auto ptr = summary.stations.begin(); ptr != summary.stations.end(); ptr++) {
        json += '"';
        json += longToHex(ptr->first);
        json += '"';
        json += " : ";
        json += std::to_string(ptr->second.bytes);
        json += ", ";
    }
    if (json.length()>2) { // remove last ; if not empty
        json = json.substr(0, json.length() - 2);
    }
    json += " }\n";
    std::cout << json;
}



void screenPrintPeriodHeader(const Summary& summary) {
    char timeStamp[100];
    time_t tt = std::chrono::duration_cast<seconds>(summary.periodEnd.time_since_epoch()).count();
    std::strftime(timeStamp, sizeof(timeStamp), "%Y-%m-%d %H:%M.%S", std::localtime(&tt));
    printf("%s  %3d secs | %3d sta | val/s %8.2f pkts %8.2f kb | corr/s  %8.2f pkts %8.2f kb\n",
           timeStamp,
           Config::get().scrPeriodLength,
           (int) summary.stations.size(),
           summary.valid.packets * 1.0 / Config::get().scrPeriodLength,
           summary.valid.bytes / 1024.0 / Config::get().scrPeriodLength,
           summary.corrupted.packets * 1.0 / Config::get().scrPeriodLength,
           summary.corrupted.bytes / 1024.0 / Config::get().scrPeriodLength
    );
}

void screenPrintPacket(const Packet& pkt) {
    static int runningNo = 0;
    char tmp[50];
    char* timeStamp = timeStampFromPkt(pkt, tmp);
    int macPktLength = pkt.lengthInclRadioTap - pkt.radioTapHeader->length;
    std::string addr1, addr2, addr3;
    getAddresses(pkt, macPktLength, addr1, addr2, addr3);
    printf("[%8d] %s | %4d | %5d bytes | %-5s | %1d / %2d | %3d tfDs | %16s | %16s | %16s | \n",
           runningNo,
           timeStamp,
           pkt.radioTapHeader->channelFreq,
           macPktLength,
           pkt.crc ? "valid" : "corr",
           pkt.macHeader->type,
           pkt.macHeader->subtype,
           pkt.macHeader->toFromDs,
           addr1.c_str(),
           addr2.c_str(),
           addr3.c_str()
    );
    runningNo++;
}


void txtLogStationSet(const StationSet& stationSet) {
    // create path from summary date
    time_t dt = std::chrono::duration_cast<seconds>(stationSet.periodEnd.time_since_epoch()).count();
    time_t dt_date = dt - 1;  // -1 sec to make the 00:00 end time go into previous day
    char fileDate[20];
    std::strftime(fileDate, sizeof(fileDate), "%Y-%m-%d", std::localtime(&dt_date));
    std::string fileName = Config::get().dbDir + "/" + fileDate + ".log";
    std::ofstream ofs{fileName, std::ofstream::app};
    char buffer[100];
    for (auto ptr = stationSet.stations.begin(); ptr != stationSet.stations.end(); ptr++) {
        sprintf(buffer, "%d %s %llu\n",
                (uint32_t) dt,
                longToHex(ptr->first).c_str(),
                ptr->second
        );
        ofs << buffer;
    }
    ofs.close();
}


void txtLogAllStationsEver(const std::map<uint64_t, SeenTimes>& all){
    // sort out old lastSeens
    std::time_t maxAge = std::time(nullptr);
    maxAge = maxAge - (maxAge % (24 * 3600)) - Config::get().allMacKeepDays * 24 * 3600;
    std::map<uint64_t, SeenTimes> filtered;
    for (auto ptr = all.begin(); ptr != all.end(); ptr++) {
        if (ptr->second.last > maxAge) {
            filtered.insert(*ptr);
        }
    }

    // file
    std::string path = Config::get().dbDir + "/" + Config::get().allStationsEver;
    std::ofstream ofs{path, std::ofstream::out};
    if (!ofs.is_open()) {
        std::cout << "*** writing all stations log to " << path << " failed" << std::endl;
        return;
    }
    for (auto ptr = all.begin(); ptr != all.end(); ptr++) {
        std::string line = longToHex(ptr->first) + " " + std::to_string(ptr->second.first) + " " +
                           std::to_string(ptr->second.last) + "\n";
        ofs << line.c_str();
    }
};


char* timeStampFromPkt(const Packet& pkt, char* timeStamp) {
    t_point pkt_t_point = t_point();
    pkt_t_point = pkt_t_point + microseconds(pkt.timeStampMicroSecs);
    time_t tt = system_clock::to_time_t(pkt_t_point);
    tm* ptm = localtime(&tt);
    strftime(timeStamp, 50, "%H:%M:%S", ptm);
    int32_t micros = pkt.timeStampMicroSecs % 1000000;
    std::string microStr = std::to_string(micros);
    const int32_t lengthMicro = microStr.length();
    for (int i = 0; i < 6 - lengthMicro; ++i) {
        microStr = '0' + microStr;
    }
    strcat(timeStamp, ".");
    strcat(timeStamp, microStr.c_str());
    return timeStamp;

}


void getAddresses(const Packet& pkt, int32_t macPktLength, std::string& addr1, std::string& addr2, std::string& addr3) {
    addr1 = addr2 = addr3 = "-";
    if (macPktLength >= 14) { addr1 = longToHex(addressToLong(const_cast<u_char*>(pkt.macHeader->addr1))); }
    if (macPktLength >= 20) { addr2 = longToHex(addressToLong(const_cast<u_char*>(pkt.macHeader->addr2))); }
    if (macPktLength >= 26) { addr3 = longToHex(addressToLong(const_cast<u_char*>(pkt.macHeader->addr3))); }
}


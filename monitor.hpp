//
// Created by Thomas Natter on 8/3/16.
//

#ifndef IRUKA_MONITOR_HPP
#define IRUKA_MONITOR_HPP

#include <fstream>
#include "config.hpp"


sqlite3* db2;


void dbCreateSysupTable() {
    char *errMsg;
    sqlite3_open(Config::get().dbName.c_str(), &db2);
    std::string sql = "CREATE TABLE IF NOT EXISTS sysup(ts INTEGER, secs INTEGER, PRIMARY KEY (ts));";
    int r = sqlite3_exec(db2, sql.c_str(), NULL, NULL, &errMsg);
    if (r != 0) std::cout << "*** error during sysup table creation: " << errMsg << "\n";
    sqlite3_close(db2);
}



// add entry to filed details to ensure that empty periods also get an entry, so allowing
// to see difference between no packets and system not running
void monitor(uint32_t startTime) {
    dbCreateSysupTable();
    startTime = startTime - startTime % Config::get().dbPeriodLength + Config::get().dbPeriodLength;
    char *errMsg;
    std::string sql = "";
    while (true) {
        if (time(nullptr) > startTime) {
            sqlite3_open("papageno.db", &db2);
            sql = "INSERT INTO sysup (ts, secs) VALUES (";
            sql += std::to_string(startTime);
            sql += ", ";
            sql += std::to_string(Config::get().dbPeriodLength);
            sql += ");";
            int r = sqlite3_exec(db2, sql.c_str(), NULL, NULL, &errMsg);
            if (r != 0) std::cout << "*** error during sysup table insert: " << errMsg << "\n";
            sqlite3_close(db2);
            startTime += Config::get().dbPeriodLength;
            std::this_thread::sleep_for(std::chrono::milliseconds(((startTime - time(nullptr)) * 1000)));
        }
    }
}



#endif //IRUKA_MONITOR_HPP


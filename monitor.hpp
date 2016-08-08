//
// Created by Thomas Natter on 8/3/16.
//

#ifndef IRUKA_MONITOR_HPP
#define IRUKA_MONITOR_HPP

#include <fstream>
#include "config.hpp"


std::string getFileName(const time_t epoch){
    char fileDate[20];
    std::strftime(fileDate, sizeof(fileDate), "%Y-%m-%d", std::localtime(&epoch));
    return Config::get().dbDir + "/" + fileDate + ".log";

}

// add entry to filed details to ensure that empty periods also get an entry, so allowing
// to see difference between no packets and system not running
void monitor(uint32_t startTime) {
    startTime = startTime - startTime % Config::get().dbPeriodLength + Config::get().dbPeriodLength;
    while (true) {
        if (time(nullptr) > startTime) {
            std::ofstream ofs{getFileName(startTime), std::ofstream::app};
            char buffer[100];
            sprintf(buffer, "%d %llu %d\n",
                    startTime,
                    (uint64_t) 0xFFFFFFFFFFFF,
                    1
            );
            ofs << buffer;
            ofs.close();
            startTime += Config::get().dbPeriodLength;
            std::this_thread::sleep_for(std::chrono::milliseconds(((startTime - time(nullptr)) * 1000)));
        }
    }
}



#endif //IRUKA_MONITOR_HPP


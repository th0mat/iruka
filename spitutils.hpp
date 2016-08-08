//
// Created by Thomas Natter on 3/23/16.
//

#ifndef SPITTER_SPITUTILS_H
#define SPITTER_SPITUTILS_H

#include <iostream>
#include "spitter.hpp"


std::string longToHex(const uint64_t&);

void txtLogStationSet(const StationSet&);
void txtLogAllStationsEver(const std::map<uint64_t, SeenTimes>&);


void screenPrintPeriodDetails(const Summary&);
void screenPrintPeriodJSON(const Summary&);
void screenPrintPeriodHeader(const Summary&);
void screenPrintPacket(const Packet&);

void dbLogSession();
void dbLogPeriod(const Summary&);
void dbLogPacket(const Packet&);



char* timeStampFromPkt(const Packet&, char*);

uint64_t addressToLong(const u_char*);


#endif //SPITTER_SPITUTILS_H

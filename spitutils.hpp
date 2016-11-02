//
// Created by Thomas Natter on 3/23/16.
//

#ifndef SPITTER_SPITUTILS_H
#define SPITTER_SPITUTILS_H

#include <iostream>
#include "spitter.hpp"
#include "sqlite3.h"


std::string longToHex(const uint64_t&);


void screenPrintPeriodDetails(const scrSummary&);
void screenPrintPeriodJSON(const scrSummary&);
void screenPrintPeriodHeader(const scrSummary&);
void screenPrintPacket(const Packet&);

void dbCreateTrafficTable();
void dbLogStationSet(const dbSummary&);


char* timeStampFromPkt(const Packet&, char*);

uint64_t addressToLong(const u_char*);


#endif //SPITTER_SPITUTILS_H

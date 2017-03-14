//
// Created by Thomas Natter on 3/20/16.
//
#include "config.hpp"
#include "spitter.hpp"
#include <csignal>


// signal handling
void signalHandler( int signum ) {
    std::cout << "\nInterrupt signal (" << signum << ") received.\n";
    if (Config::get().hop) std::system("sudo /bin/bash -c 'ifconfig en0 up'");
    exit(signum);
}


void defaultOverride(int argc, char* argv[]){
    // set the interface
    std::string dev(argv[1]);
    Config::get().device = dev;
    if (argc == 2) return;
    std::string input = argv[2];
    if (input == "json") {
        Config::get().scrPeriodLength = 2;
        Config::get().outScrPeriodDetails = false;
        Config::get().outScrPkts = false;
        Config::get().outScrPeriodHdr = false;
        Config::get().outScrPeriodJSON = true;
        Config::get().dbLog = false;
    }
}


// program start
int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "*** missing wi-fi interface argument\n";
        exit(1);
    }
    defaultOverride(argc, argv);
    std::signal(SIGINT, signalHandler);
    if (Config::get().dbLog && (Config::get().dbDir != "")) {
        std::string mkDataDir = "mkdir -p " + Config::get().dbDir;
        std::system(mkDataDir.c_str());
    }
    startSpitting();
}


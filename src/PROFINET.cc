#include "PROFINET.h"
#include "events.bif.h"

using namespace analyzer::profinet;

PROFINET_Analyzer::PROFINET_Analyzer(zeek::Connection* c): zeek::analyzer::Analyzer("PROFINET", c) {
    interp = new binpac::PROFINET::PROFINET_Conn(this);
    }

PROFINET_Analyzer::~PROFINET_Analyzer() {
    delete interp;
    }

void PROFINET_Analyzer::Done() {
    Analyzer::Done();
    }

void PROFINET_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip, int caplen) {
    Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

    try {
        interp->NewData(orig, data, data + len);
        }
    catch(const binpac::Exception& e) {
        AnalyzerViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
        }
    }


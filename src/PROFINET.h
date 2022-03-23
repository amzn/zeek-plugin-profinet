#ifndef ANALYZER_PROTOCOL_PROFINET_H
#define ANALYZER_PROTOCOL_PROFINET_H

#include "events.bif.h"
#if ZEEK_VERSION_NUMBER >= 40100
#include <zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h>
#else
#include <zeek/analyzer/protocol/udp/UDP.h>
#endif
#include "profinet_pac.h"

namespace analyzer {
    namespace profinet {
        class PROFINET_Analyzer : public zeek::analyzer::Analyzer {
            public:
                PROFINET_Analyzer(zeek::Connection* conn);
                virtual ~PROFINET_Analyzer();

                virtual void Done();
                virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip, int caplen);

                static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn) {
                    return new PROFINET_Analyzer(conn);
                    }

            protected:
                binpac::PROFINET::PROFINET_Conn* interp;
            };
        }
    }

#endif

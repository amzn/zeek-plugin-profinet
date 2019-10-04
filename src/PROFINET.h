#ifndef ANALYZER_PROTOCOL_PROFINET_H
#define ANALYZER_PROTOCOL_PROFINET_H

#include "events.bif.h"
#include "analyzer/protocol/udp/UDP.h"
#include "profinet_pac.h"

namespace analyzer { 
    namespace profinet {
        class PROFINET_Analyzer : public analyzer::Analyzer {
            public:
                PROFINET_Analyzer(Connection* conn);
                virtual ~PROFINET_Analyzer();

                virtual void Done();
                virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen);

                static analyzer::Analyzer* Instantiate(Connection* conn) { 
                    return new PROFINET_Analyzer(conn);
                    }

            protected:
                binpac::PROFINET::PROFINET_Conn* interp;
            };
        } 
    }

#endif

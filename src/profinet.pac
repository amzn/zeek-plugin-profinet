%include zeek/binpac.pac
%include zeek/zeek.pac

%extern{
    #include "events.bif.h"
    %}

analyzer PROFINET withcontext {
    connection: PROFINET_Conn;
    flow:       PROFINET_Flow;
    };

%include profinet-protocol.pac
%include profinet-analyzer.pac

%include binpac.pac
%include bro.pac

%extern{
    #include "events.bif.h"
    %}

analyzer PROFINET withcontext {
    connection: PROFINET_Conn;
    flow:       PROFINET_Flow;
    };

%include profinet-protocol.pac
%include profinet-analyzer.pac

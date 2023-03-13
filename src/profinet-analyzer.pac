## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

connection PROFINET_Conn(zeek_analyzer: ZeekAnalyzer) {
    upflow   = PROFINET_Flow(true);
    downflow = PROFINET_Flow(false);
    };

%header{
    #define SLAVE     0x29
    #define MASTER     0x2b
    %}

flow PROFINET_Flow(is_orig: bool) {
    # flowunit = PROFINET_PDU(is_orig) withcontext(connection, this);
    datagram = PROFINET_PDU(is_orig) withcontext(connection, this);

    function profinet_dce_rpc(header: Profinet_DCE_RPC): bool %{
        if(::profinet_dce_rpc) {
            connection()->zeek_analyzer()->AnalyzerConfirmation();
            zeek::BifEvent::enqueue_profinet_dce_rpc(connection()->zeek_analyzer(),
                                                     connection()->zeek_analyzer()->Conn(),
                                                     is_orig(),
                                                     ${header.version},
                                                     ${header.packet_type},
                                                     (${header.object_uuid.part1}),
                                                     (${header.object_uuid.part2}),
                                                     (${header.object_uuid.part3}),
                                                     (${header.object_uuid.part4}),
                                                     to_stringval(${header.object_uuid.part5}),
                                                     (${header.interface_uuid.part1}),
                                                     (${header.interface_uuid.part2}),
                                                     (${header.interface_uuid.part3}),
                                                     (${header.interface_uuid.part4}),
                                                     to_stringval(${header.interface_uuid.part5}),
                                                     (${header.activity_uuid.part1}),
                                                     (${header.activity_uuid.part2}),
                                                     (${header.activity_uuid.part3}),
                                                     (${header.activity_uuid.part4}),
                                                     to_stringval(${header.activity_uuid.part5}),
                                                     ${header.server_boot_time},
                                                     ${header.operation_number}
                                                     );
            }

        return true;
        %}

    function profinet(header: PROFINET): bool %{
        if(::profinet) {
            connection()->zeek_analyzer()->AnalyzerConfirmation();
            zeek::BifEvent::enqueue_profinet(connection()->zeek_analyzer(),
                                             connection()->zeek_analyzer()->Conn(),
                                             is_orig(),
                                             ${header.block_header.operation_type},
                                             ${header.block_header.version_high},
                                             ${header.block_header.version_low},
                                             ${header.slot_number},
                                             ${header.subslot_number},
                                             ${header.index}
                                             );
        }

        return true;
        %}

    function profinet_debug(raw_data: bytestring): bool %{
        if(::profinet_debug) {
            connection()->zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("unknown ProfiNet"));
            zeek::BifEvent::enqueue_profinet_debug(connection()->zeek_analyzer(),
                                                   connection()->zeek_analyzer()->Conn(),
                                                   is_orig(),
                                                   to_stringval(raw_data)
                                                   );
        }

        return true;
        %}

    };

refine typeattr Profinet_DCE_RPC += &let {
     proc: bool = $context.flow.profinet_dce_rpc(this);
     };

refine typeattr PROFINET += &let {
    proc: bool = $context.flow.profinet(this);
    };

refine typeattr Debug += &let {
    ##! proc: bool = $context.flow.profinet_debug(raw_data);
    };

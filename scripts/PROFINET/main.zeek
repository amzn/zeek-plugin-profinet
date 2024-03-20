##! Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
##! SPDX-License-Identifier: BSD-3-Clause

##! Implements base functionality for Profinet analysis.
##! Generates the profinet_dce_rpc.log file, containing some information about the Profinet_DCE_RPC headers.
##! Generates the profinet.log file, containing some information about the Profinet communication.
##! Generates the profinet_debug.log file, containing some information about unknown/missed profinet data.

module Profinet;

export {
    redef enum Log::ID += {
        Log_Profinet_DCE_RPC,
        Log_Profinet,
        Log_Profinet_Debug
        };

    ## distributed computing environment / remote procedure call info
    type Profinet_DCE_RPC: record {
        ts              : time &log;                ## Timestamp for when the event happened.
        uid             : string &log;              ## Unique ID for the connection.
        id              : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        version         : count &optional &log;
        packet_type     : count &optional &log;
        object_uuid     : string &optional &log;
        interface_uuid  : string &optional &log;
        activity_uuid   : string &optional &log;
        server_boot_time: count &optional &log;
        operation       : string &optional &log;
        };

    ## Event that can be handled to access the profinet record as it is sent to the loggin framework.
    global log_profinet_dce_rpc: event(rec: Profinet_DCE_RPC);

    global log_policy_dce_rpc: Log::PolicyHook;

    ## header info
    type Profinet: record {
        ts              : time &log;                ## Timestamp for when the event happened.
        uid             : string &log;              ## Unique ID for the connection.
        id              : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        operation_type  : string &optional &log;
        block_version   : string &optional &log;
        slot_number     : count &optional &log;
        subslot_number  : count &optional &log;
        index           : string &optional &log;
        };

    ## Event that can be handled to access the profinet record as it is sent to the loggin framework.
    global log_profinet: event(rec: Profinet);

    global log_policy: Log::PolicyHook;

    ## header info
    type Profinet_Debug: record {
        ts      : time &log;                ## Timestamp for when the event happened.
        uid     : string &log;              ## Unique ID for the connection.
        id      : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        raw_data: string &optional &log;
        };

    ## Event that can be handled to access the profinet record as it is sent to the loggin framework.
    global log_profinet_debug: event(rec: Profinet_Debug);

    global log_policy_debug: Log::PolicyHook;
    }

redef record connection += {
    profinet_dce_rpc: Profinet_DCE_RPC &optional;
    profinet        : Profinet &optional;
    profinet_debug  : Profinet_Debug &optional;
    };

## define listening ports
const ports = {
    34964/udp
    };
redef likely_server_ports += {
    ports
    };

event zeek_init() &priority=5 {
    Log::create_stream(Profinet::Log_Profinet_DCE_RPC,
                        [$columns=Profinet_DCE_RPC,
                        $ev=log_profinet_dce_rpc,
                        $path="profinet_dce_rpc",
                        $policy=log_policy_dce_rpc]);
    Log::create_stream(Profinet::Log_Profinet,
                        [$columns=Profinet,
                        $ev=log_profinet,
                        $path="profinet",
                        $policy=log_policy]);
    Log::create_stream(Profinet::Log_Profinet_Debug,
                        [$columns=Profinet_Debug,
                        $ev=log_profinet_debug,
                        $path="profinet_debug",
                        $policy=log_policy_debug]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_PROFINET, ports);
    }

##! Profinet_DCE_RPC response
event profinet_dce_rpc(c:connection, is_orig: bool,
                        version: count,
                        packet_type: count,
                        object_uuid_part1: count,
                        object_uuid_part2: count,
                        object_uuid_part3: count,
                        object_uuid_part4: count,
                        object_uuid_part5: string,
                        interface_uuid_part1: count,
                        interface_uuid_part2: count,
                        interface_uuid_part3: count,
                        interface_uuid_part4: count,
                        interface_uuid_part5: string,
                        activity_uuid_part1: count,
                        activity_uuid_part2: count,
                        activity_uuid_part3: count,
                        activity_uuid_part4: count,
                        activity_uuid_part5: string,
                        server_boot_time: count,
                        operation_number: count
                        ) {
    if(!c?$profinet_dce_rpc) {
        c$profinet_dce_rpc = [$ts=network_time(), $uid=c$uid, $id=c$id];
        add c$service["profinet_dce_rpc"];
        }

    c$profinet_dce_rpc$ts = network_time();
    c$profinet_dce_rpc$version = version;
    c$profinet_dce_rpc$packet_type = packet_type;
    c$profinet_dce_rpc$object_uuid = fmt("%x-%x-%x-%x-%s", (object_uuid_part1),
                                        (object_uuid_part2),
                                        (object_uuid_part3),
                                        (object_uuid_part4),
                                        bytestring_to_hexstr(object_uuid_part5));
    c$profinet_dce_rpc$interface_uuid = fmt("%x-%x-%x-%x-%s", (interface_uuid_part1),
                                            (interface_uuid_part2),
                                            (interface_uuid_part3),
                                            (interface_uuid_part4),
                                            bytestring_to_hexstr(interface_uuid_part5));
    c$profinet_dce_rpc$activity_uuid = fmt("%x-%x-%x-%x-%s", (activity_uuid_part1),
                                            (activity_uuid_part2),
                                            (activity_uuid_part3),
                                            (activity_uuid_part4),
                                            bytestring_to_hexstr(activity_uuid_part5));
    c$profinet_dce_rpc$server_boot_time = server_boot_time;
    c$profinet_dce_rpc$operation = operations[operation_number];

    Log::write(Log_Profinet_DCE_RPC, c$profinet_dce_rpc);
    }

##! general Profinet header
event profinet(c:connection, is_orig: bool,
                operation_type: count,
                version_high: count,
                version_low: count,
                slot_number: count,
                subslot_number: count,
                index: count
                ) {
    if(!c?$profinet) {
        c$profinet = [$ts=network_time(), $uid=c$uid, $id=c$id];
        add c$service["profinet"];
        }

    c$profinet$ts = network_time();
    c$profinet$operation_type = operation_types[operation_type];
    c$profinet$block_version = fmt("%d.%d", version_high, version_low);
    c$profinet$slot_number = slot_number;
    c$profinet$subslot_number = subslot_number;
    c$profinet$index = indexes[index];

    Log::write(Log_Profinet, c$profinet);
    }

##! general Profinet debug
event profinet_debug(c:connection, is_orig: bool, raw_data: string) {
    if(!c?$profinet_debug) {
        c$profinet_debug = [$ts=network_time(), $uid=c$uid, $id=c$id];
        add c$service["profinet"];
        }

    c$profinet_debug$ts = network_time();
    c$profinet_debug$raw_data = raw_data;

    Log::write(Log_Profinet_Debug, c$profinet_debug);
    }

event connection_state_remove(c: connection) &priority=-5 {
    if(c?$profinet) {
        delete c$profinet;
        }
    }

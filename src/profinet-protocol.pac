## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

##############################
#         CONSTANTS          #
##############################

enum block_header_codes {
    IOD_WRITE_REQUEST    = 0x0008,
    IOD_WRITE_RESPONSE    = 0x8008,
    IOD_READ_REQUEST    = 0x0009,
    IOD_READ_RESPONSE    = 0x8009
    };

##############################
##        RECORD TYPES       #
##############################

## All multiple byte fields are set in little endian order

type PROFINET_PDU(is_orig: bool) = case is_orig of {
    true  -> request    : PROFINET_Request;
    false -> response   : PROFINET_Response;
    } &byteorder=littleendian;

##type PROFINET_UDP = record {
##    data: Common_Packet_Format;
##    } &byteorder=littleendian;

# switch for the request portion
type PROFINET_Request = record {
    profinet_dce_rpc: Profinet_DCE_RPC;
    profinet        : PROFINET;
    debug           : Debug;
    } &byteorder=bigendian;

# switch for the response portion
type PROFINET_Response = record {
    profinet_dce_rpc: Profinet_DCE_RPC;
    profinet        : PROFINET;
    debug           : Debug;
    } &byteorder=bigendian;

type Profinet_DCE_RPC = record {
    version             : uint8;
    packet_type         : uint8;
    flags1              : uint8;
    flags2              : uint8;
    data_representation : Data_Representation;
    serial_high         : uint8;
    object_uuid         : UUID;
    interface_uuid      : UUID;
    activity_uuid       : UUID;
    server_boot_time    : uint32;
    interface_version   : uint32;
    sequence_number     : uint32;
    operation_number    : uint16; ##! 0x03 is write, 0x05 is read
    interface_hint      : uint16;
    activity_hint       : uint16;
    fragment_len        : uint16; ##! length of payload
    fragment_number     : uint16;
    auth_protocol       : uint8;
    serial_low          : uint8;
    } &byteorder=littleendian;

type UUID = record {
    part1   : uint32;
    part2   : uint16;
    part3   : uint16;
    part4   : uint16 &byteorder=bigendian;
    part5   : bytestring &length=6;
    } &byteorder=littleendian;

type Data_Representation = record {
    byte_order      : uint8; ##! 0x10 is little endian
    character       : uint8;
    floating_point  : uint8;
    } &byteorder=bigendian;

type PROFINET = record {
    args_maximum    : uint32;
    args_length     : uint32;
    array           : Array;
    block_header    : Block_Header;
    sequence_number : uint16;
    ar_uuid         : bytestring &length=16;
    api             : uint32;
    slot_number     : uint16;
    subslot_number  : uint16;
    padding1        : bytestring &length=2;
    index           : uint16;
    record_data_len : uint32;
    padding2        : case(block_header.operation_type) of {
                        IOD_WRITE_REQUEST   -> iod_write_request_value  : bytestring &length=24;
                        IOD_WRITE_RESPONSE  -> iod_write_response_value : bytestring &length=16;
                        IOD_READ_REQUEST    -> iod_read_request_value   : bytestring &length=8;
                        IOD_READ_RESPONSE   -> iod_read_response_value  : bytestring &length=20;
                        default             -> default_value            : empty;
                        };
    data            : bytestring &restofdata;
    } &byteorder=bigendian;

type Array = record {
    maximum_count   : uint32;
    offset          : uint32;
    actual_count    : uint32;
    } &byteorder=littleendian;

type Block_Header = record {
    operation_type  : uint16;
    len             : uint16;
    version_high    : uint8;
    version_low     : uint8;
    } &byteorder=bigendian;

type Data_Submodule = record {
    block_header                : Block_Header;
    number_of_apis              : uint16;
    api                         : uint32;
    number_of_modules           : uint16;
    subslot_number              : uint16;
    submodule_identifier_number : uint32;
    } &byteorder=bigendian;

type Subslot = record {
    slot_number             : uint16;
    module_identifier       : uint32;
    number_of_submodules    : uint16;
    } &byteorder=bigendian;

type Debug = record {
    raw_data: bytestring &restofdata;
    };


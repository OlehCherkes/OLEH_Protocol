#include "config.h"
#include <epan/packet.h>

#define OLEH_PORT 7777       // UDP port

#define FIRST_FLAG      0x01
#define SECOND_FLAG     0x02
#define THIRD_FLAG      0x04

static int proto_oleh = -1;      // stores our protocol handle, identifier

/*  registering data structures */
static int ett_oleh = -1;
static int hf_oleh_hdr_version = -1;
static int hf_oleh_hdr_type = -1;

static int hf_oleh_hdr_flags = -1;
static int hf_oleh_flags_first   = -1;
static int hf_oleh_flags_second  = -1;
static int hf_oleh_flags_third = -1;

static int hf_oleh_hdr_bool = -1;
static int hf_oleh_dt_len = -1;
static int hf_oleh_data = -1;

/*   add details to the output  */
static const value_string packetversions[] = {
    { 1, "Version 1" },
    { 2, "Version 2" },
    { 3, "Version 3" },
    { 0, NULL }
};

// dissecting function
static int dissect_oleh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OLEH");    //  used to set the Wireshark Protocol column to "OLEH"
    col_clear(pinfo->cinfo, COL_INFO);   //  Clear out stuff in the info column

    int offset = 0;

    proto_item *ti = proto_tree_add_item(tree, proto_oleh, tvb, 0, -1, FALSE);  //  add the new subtree
    proto_tree *oleh_tree = proto_item_add_subtree(ti, ett_oleh);
    proto_tree_add_item(oleh_tree, hf_oleh_hdr_version, tvb, offset, 1, FALSE); offset += 1;
    proto_tree_add_item(oleh_tree, hf_oleh_hdr_type, tvb, offset, 1, FALSE); offset += 1;

    proto_tree_add_item(oleh_tree, hf_oleh_hdr_flags, tvb, offset, 1, FALSE);
    proto_tree_add_item(oleh_tree, hf_oleh_flags_first, tvb, offset, 1, FALSE);
    proto_tree_add_item(oleh_tree, hf_oleh_flags_second, tvb, offset, 1, FALSE);
    proto_tree_add_item(oleh_tree, hf_oleh_flags_third, tvb, offset, 1, FALSE); offset += 1;

    proto_tree_add_item(oleh_tree, hf_oleh_hdr_bool, tvb, offset, 1, FALSE); offset += 1;
    proto_tree_add_item(oleh_tree, hf_oleh_dt_len, tvb, offset, 4, TRUE);  offset += 4;
    proto_tree_add_item(oleh_tree, hf_oleh_data, tvb, offset, -1, FALSE);

    return tvb_captured_length(tvb);
}

//  register the protocol in Wireshark
void proto_register_oleh(void)
{
    static hf_register_info hf[] = {
        { &hf_oleh_hdr_version,
            { "OLEH Header Version", "oleh.hdr.version",
            FT_UINT8, BASE_DEC,
            VALS(packetversions), 0x0,
            NULL, HFILL }
        },
        { &hf_oleh_hdr_type,
            { "OLEH Header Type", "oleh.hdr.type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oleh_hdr_flags,
            { "OLEH Header Flags", "oleh.hdr.flags",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oleh_flags_first,
            { "First flag", "oleh.hdr.flags.first",
            FT_BOOLEAN, FT_INT8,
            NULL, FIRST_FLAG,
            NULL, HFILL }
        },
        { &hf_oleh_flags_second,
            { "Second flag", "oleh.hdr.flags.second",
            FT_BOOLEAN, FT_INT8,
            NULL, SECOND_FLAG,
            NULL, HFILL }
        },
        { &hf_oleh_flags_third,
            { "Third flag", "oleh.hdr.flags.third",
            FT_BOOLEAN, FT_INT8,
            NULL, THIRD_FLAG,
            NULL, HFILL }
        },
        { &hf_oleh_hdr_bool,
            { "OLEH Header Boolean", "oleh.hdr.bool",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oleh_dt_len,
            { "OLEH Data Length", "oleh.dt_len",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_oleh_data,
            { "OLEH Data", "oleh.data",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = { &ett_oleh };

    proto_oleh = proto_register_protocol (
        "OLEH Protocol", /* name       */
        "OLEH",          /* short_name */
        "oleh"           /* filter_name*/
        );

    /*  registration of arrays  */
    proto_register_field_array(proto_oleh, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

//  performs dissector registration for the "oleh" protocol
void proto_reg_handoff_oleh(void)
{
    static dissector_handle_t oleh_handle;  //  to get a handle to protocol oleh

    oleh_handle = create_dissector_handle(dissect_oleh, proto_oleh);      //  a handle is created for the dissector and linked to the "oleh" protocol
    dissector_add_uint("udp.port", OLEH_PORT, oleh_handle);      //  specifies that this dissector will be applied to UDP packets with port OLEH_PORT
}


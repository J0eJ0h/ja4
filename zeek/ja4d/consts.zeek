module FINGERPRINT::JA4D;

export {
    global DHCP_MESSAGE_MAP: table[count] of string = {
        [1] = "disco", # DHCPDISCOVER
        [2] = "offer", # DHCPOFFER
        [3] = "reqst", # DHCPREQUEST
        [4] = "decln", # DHCPDECLINE
        [5] = "dpack", # DHCPACK
        [6] = "dpnak", # DHCPNAK
        [7] = "relse", # DHCPRELEASE
        [8] = "infor", # DHCPINFORM
        [9] = "frenw", # DHCPFORCERENEW
        [10] = "lqery", # DHCPLEASEQUERY
        [11] = "lunas", # DHCPLEASEUNASSIGNED
        [12] = "lunkn", # DHCPLEASEUNKNOWN
        [13] = "lactv", # DHCPLEASEACTIVE
        [14] = "blklq", # DHCPBULKLEASEQUERY
        [15] = "lqdon", # DHCPLEASEQUERYDONE
        [16] = "actlq", # DHCPACTIVELEASEQUERY
        [17] = "lqsta", # DHCPLEASEQUERYSTATUS
        [18] = "dhtls", # DHCPTLS
    };

    global DHCP_SKIP_OPTIONS: set[count] = {
        53,
        255,
        50,
        81,
    };

    global DHCPV6_MESSAGE_MAP: table[count] of string = {
        [1] = "solct",
        [2] = "advrt",
        [3] = "reqst",
        [4] = "confm",
        [5] = "renew",
        [6] = "rebnd",
        [7] = "reply",
        [8] = "relse",
        [9] = "decln",
        [10] = "recon",
        [11] = "inreq",
        [12] = "rlayf",
        [13] = "rlayr",
        [14] = "query",
        [15] = "qrply",
        [16] = "qdone",
        [17] = "qdata",
        [18] = "rereq",
        [19] = "rrply",
        [20] = "v4qry",
        [21] = "v4res",
        [22] = "acqry",
        [23] = "sttls",
        [24] = "bdudp",
        [25] = "brply",
        [26] = "poreq",
        [27] = "pores",
        [28] = "urqst",
        [29] = "ureqa",
        [30] = "udone",
        [31] = "conne",
        [32] = "connr",
        [33] = "dconn",
        [34] = "state",
        [35] = "conta",
        [36] = "arinf",
        [37] = "arrep",
    };
    }
# Copyright (c) 2025, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4+ by John Althouse
# Zeek script by Jo Johnson

module DHCP;

export {
    type DHCPv6Msg: record {
        msg_type: count;
        transaction_id: string;
        hop_count: count;
        link_address: addr;
        peer_address: addr;
    };

    type DHCPv6Options: record {
        options: vector of count;
        client_id: string;
        server_id: string;
        request_list: vector of count;
        has_ip: bool;
        fqdn_flags: count;
        vendor_class: string;
        hostname: string;
    };

    global dhcpv6_message: event(
        c: connection,
        is_orig: bool,
        msg: DHCPv6Msg,
        options: DHCPv6Options
    );
}

module FINGERPRINT::JA4D;

export {
  # The fingerprint context and logging format
  type Info: record {
    # The connection uid which this fingerprint represents
    ts: time &log &optional;
    uid: string &log &optional;
    id: conn_id &log &optional;

    # The ssh fingerprint
    ja4d: string &log &default="";
    client_mac: string &log &default="";
    requested_ip: addr &log &optional;
    vendor_class_id: string &log &default="";
    hostname: string &log &default="";
  };


  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4d: event(rec: Info);
  global log_policy: Log::PolicyHook;

}

# Create the log stream and file
event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4D::LOG,
    [$columns=FINGERPRINT::JA4D::Info, $ev=log_fingerprint_ja4d, $path="ja4d", $policy=log_policy]
  );
  Analyzer::register_for_ports(Analyzer::get_tag("spicy_DHCPv6"), set(546/udp, 547/udp));
}


function get_dhcp_message_type(msg: DHCP::Msg): string {
  if (!msg?$m_type) {
    return "00000";
  }

  if (msg$m_type in FINGERPRINT::JA4D::DHCP_MESSAGE_MAP) {
    return FINGERPRINT::JA4D::DHCP_MESSAGE_MAP[msg$m_type];
  }
  
  return fmt("%05d", msg$m_type); 

}

function get_max_message_size(options: DHCP::Options): string {
  if (options?$max_msg_size) {
    if (options$max_msg_size > 9999) {
      return "9999";
    }
    return fmt("%04d", options$max_msg_size);
  }
  return "0000";
}

function get_request_ip(options: DHCP::Options): string {
  if (options?$addr_request) {
    return "i";
  }
  return "n";
}

function get_FQDN(options: DHCP::Options): string {
  if (options?$client_fqdn) {
    return "d";
  }
  return "n";
}

function get_option_list(options: DHCP::Options): string {
  if (!options?$options) {
    # Not sure this is actually possible since you need at least option 53 to be DHCP and not just BOOTP
    return "00";
  }
  return FINGERPRINT::vector_of_count_to_str(options$options, "%d", "-", FINGERPRINT::JA4D::DHCP_SKIP_OPTIONS);
}

function get_parameter_list(options: DHCP::Options): string {
  if(!options?$param_list || |options$param_list| == 0) {
    return "00";
  }
  return FINGERPRINT::vector_of_count_to_str(options$param_list, "%d", "-");
}

function get_dhcpv6_message_type(msg: DHCP::DHCPv6Msg): string {
    if (msg$msg_type in FINGERPRINT::JA4D::DHCPV6_MESSAGE_MAP) {
        return FINGERPRINT::JA4D::DHCPV6_MESSAGE_MAP[msg$msg_type];
    }
    return fmt("%05d", msg$msg_type);
}

function get_v6_duid_length(options: DHCP::DHCPv6Options): string {
    if (options$client_id == "") {
        return "0000";
    }
    # client_id is hex string, so length in bytes is length / 2
    local len = |options$client_id| / 2;
    if (len > 9999) {
        return "9999";
    }
    return fmt("%04d", len);
}

function get_v6_request_ip(options: DHCP::DHCPv6Options): string {
    return options$has_ip ? "i" : "n";
}

function get_v6_fqdn(options: DHCP::DHCPv6Options): string {
    return options$fqdn_flags != 0 ? "d" : "n";
}

function get_v6_option_list(options: DHCP::DHCPv6Options): string {
    if (|options$options| == 0) {
        return "00";
    }
    return FINGERPRINT::vector_of_count_to_str(options$options, "%d", "-");
}

function get_v6_parameter_list(options: DHCP::DHCPv6Options): string {
    if (|options$request_list| == 0) {
        return "00";
    }
    return FINGERPRINT::vector_of_count_to_str(options$request_list, "%d", "-");
}

function extract_mac_from_duid(duid: string): string {
    # duid is hex string
    if (|duid| < 8) return "";
    local duid_type = hexstr_to_count(duid[0:4]);
    local mac_hex = "";
    if (duid_type == 1) { # LLT: Type(2), HWType(2), Time(4), LLAddr(Variable)
        if (|duid| >= 20) mac_hex = duid[|duid|-12:|duid|];
    }
    else if (duid_type == 3) { # LL: Type(2), HWType(2), LLAddr(Variable)
        if (|duid| >= 8) mac_hex = duid[|duid|-12:|duid|];
    }
    
    if (mac_hex == "") return "";
    
    return fmt("%s:%s:%s:%s:%s:%s", mac_hex[0:2], mac_hex[2:4], mac_hex[4:6], mac_hex[6:8], mac_hex[8:10], mac_hex[10:12]);
}

function do_ja4d(c: connection, msg: DHCP::Msg, options: DHCP::Options) {
  local ja4d: FINGERPRINT::JA4D::Info;
  ja4d$ts = c$start_time;
  ja4d$uid = c$uid;
  ja4d$id = c$id;
  
  if (options?$host_name) {
    ja4d$hostname = options$host_name;
  }
  if (options?$vendor_class) {
    ja4d$vendor_class_id = options$vendor_class;
  }
  if (options?$addr_request) {
    ja4d$requested_ip = options$addr_request;
  }
  if (msg?$chaddr) {
    ja4d$client_mac = msg$chaddr;
  }

  ja4d$ja4d += get_dhcp_message_type(msg) + get_max_message_size(options);
  ja4d$ja4d += get_request_ip(options)+get_FQDN(options);
  ja4d$ja4d += FINGERPRINT::delimiter;
  ja4d$ja4d += get_option_list(options);
  ja4d$ja4d += FINGERPRINT::delimiter;
  ja4d$ja4d += get_parameter_list(options);
  
  Log::write(FINGERPRINT::JA4D::LOG, ja4d);
}

function do_ja4d6(c: connection, is_orig: bool, msg: DHCP::DHCPv6Msg, options: DHCP::DHCPv6Options) {
  local ja4d: FINGERPRINT::JA4D::Info;
  ja4d$ts = c$start_time;
  ja4d$uid = c$uid;
  ja4d$id = c$id;

  local c_mac = extract_mac_from_duid(options$client_id);
  if (c_mac == "") {
      if (is_orig && c$orig?$l2_addr) {
          c_mac = c$orig$l2_addr;
      } else if (!is_orig && c$resp?$l2_addr) {
          c_mac = c$resp$l2_addr;
      }
  }
  ja4d$client_mac = c_mac;

  if (options$vendor_class != "") {
      ja4d$vendor_class_id = options$vendor_class;
  }
  if (options$hostname != "") {
      ja4d$hostname = options$hostname;
  }

  ja4d$ja4d += get_dhcpv6_message_type(msg);
  ja4d$ja4d += get_v6_duid_length(options);
  ja4d$ja4d += get_v6_request_ip(options);
  ja4d$ja4d += get_v6_fqdn(options);
  ja4d$ja4d += FINGERPRINT::delimiter;
  ja4d$ja4d += get_v6_option_list(options);
  ja4d$ja4d += FINGERPRINT::delimiter;
  ja4d$ja4d += get_v6_parameter_list(options);

  Log::write(FINGERPRINT::JA4D::LOG, ja4d);
}

# We log per DHCP message for this fingerprint instead of aggregating across a 
# DHCP conversation
event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) {
    # This is where we can add throttling or message type filtering
    do_ja4d(c, msg, options);
}

event DHCP::dhcpv6_message(c: connection, is_orig: bool, msg: DHCP::DHCPv6Msg, options: DHCP::DHCPv6Options) {
    do_ja4d6(c, is_orig, msg, options);
}

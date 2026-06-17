##! Minimal ARP logger for BeaconButty.
##!
##! Zeek 8 ships the ARP events but no shipped logging policy script. This
##! file fills the gap: hook arp_request, arp_reply, and bad_arp; emit a
##! single arp.log used by the webapp's L2 anomaly detector.
##!
##! Schema is intentionally narrow — the consumer only needs (time, ip, mac,
##! operation) to spot MAC↔IP changes, gateway impersonation, and gratuitous
##! ARP. We log the *sender* fields (SPA / SHA) for replies and requests
##! (sender of an ARP request still announces its own IP→MAC). Targets are
##! recorded too for forensic clarity.

module ARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:        time     &log;
        operation: string   &log;            # "request" | "reply" | "bad"
        src_mac:   string   &log;
        src_ip:    addr     &log &optional;
        dst_mac:   string   &log &optional;
        dst_ip:    addr     &log &optional;
        info:      string   &log &optional;  # bad_arp explanation, if any
    };
}

event zeek_init() &priority=5
{
    Log::create_stream(ARP::LOG, [$columns=Info, $path="arp"]);
}

event arp_request(mac_src: string, mac_dst: string,
                  SPA: addr, SHA: string,
                  TPA: addr, THA: string)
{
    Log::write(ARP::LOG, [
        $ts=network_time(),
        $operation="request",
        $src_mac=mac_src,
        $src_ip=SPA,
        $dst_mac=mac_dst,
        $dst_ip=TPA
    ]);
}

event arp_reply(mac_src: string, mac_dst: string,
                SPA: addr, SHA: string,
                TPA: addr, THA: string)
{
    Log::write(ARP::LOG, [
        $ts=network_time(),
        $operation="reply",
        $src_mac=mac_src,
        $src_ip=SPA,
        $dst_mac=mac_dst,
        $dst_ip=TPA
    ]);
}

event bad_arp(SPA: addr, SHA: string, TPA: addr, THA: string, explanation: string)
{
    Log::write(ARP::LOG, [
        $ts=network_time(),
        $operation="bad",
        $src_mac=SHA,
        $src_ip=SPA,
        $dst_mac=THA,
        $dst_ip=TPA,
        $info=explanation
    ]);
}

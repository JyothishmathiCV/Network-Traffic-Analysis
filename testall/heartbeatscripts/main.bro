#@load packettrack
@load base/protocols/socks
@load base/frameworks/sumstats
@load base/protocols/http
@load base/protocols/conn

global time_period: table[addr, string] of interval;
global prev_time: table[addr, string] of time;
global is_periodic: table[addr, string] of bool;
global total_requests: table[addr, string] of count;
global time_period_ip: table[addr, addr] of interval;
global prev_time_ip: table[addr, addr] of time;
global is_periodic_ip: table[addr, addr] of bool;
global total_requests_ip: table[addr, addr] of count;
redef enum Log::ID += { LOG };

type Info: record {
    source_ip: addr &log;
    destination_ip: addr &log &optional;
    destination_url: string &log &optional;
    total_requests: count &log;
    periodicity: double &log &optional;
};
global records: vector of Info;

global ind = 0;
global time_beg = network_time();

event bro_init() {
    Log::create_stream(LOG, [$columns=Info, $path="out_log_5"]);
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
    local sender_ip = c$id$orig_h;
    local dest_ip = c$id$resp_h;
    local dest_url = "";
    for ([index] in hlist) {
        if (hlist[index]$name == "HOST") {
            dest_url = hlist[index]$value;
        }
    }
    if (dest_url != "") {
        if ([sender_ip, dest_url] in prev_time) {
            if(is_periodic[sender_ip, dest_url]) {
                local time_int = c$http$ts - prev_time[sender_ip, dest_url];
                if(!([sender_ip, dest_url] in time_period))
                    time_period[sender_ip, dest_url] = time_int;
                else {
                    local threshold = 1sec;
                    local threshold_packets = 10;
                    if (!(time_int <= time_period[sender_ip, dest_url] + threshold && time_int >= time_period[sender_ip, dest_url] - threshold)) {
                        if (total_requests[sender_ip, dest_url] < threshold_packets)
                            is_periodic[sender_ip, dest_url] = F;
                    }
                }
            }
            prev_time[sender_ip, dest_url] = c$http$ts;
            ++total_requests[sender_ip, dest_url];
        } else {
            prev_time[sender_ip, dest_url] = c$http$ts;
            is_periodic[sender_ip, dest_url] = T;
            total_requests[sender_ip, dest_url] = 1;
        }
    }

    if ([sender_ip, dest_ip] in prev_time_ip) {
        if(is_periodic_ip[sender_ip, dest_ip]) {
            time_int = c$http$ts - prev_time_ip[sender_ip, dest_ip];
            if(!([sender_ip, dest_ip] in time_period_ip))
                time_period_ip[sender_ip, dest_ip] = time_int;
            else {
                threshold = 1sec;
                threshold_packets = 10;
                if (!(time_int <= time_period_ip[sender_ip, dest_ip] + threshold && time_int >= time_period_ip[sender_ip, dest_ip] - threshold))
                    if (total_requests_ip[sender_ip, dest_ip] < threshold_packets)
                        is_periodic_ip[sender_ip, dest_ip] = F;
            }
        }
        prev_time_ip[sender_ip, dest_ip] = c$http$ts;
        ++total_requests_ip[sender_ip, dest_ip];
    } else {
        prev_time_ip[sender_ip, dest_ip] = c$http$ts;
        is_periodic_ip[sender_ip, dest_ip] = T;
        total_requests_ip[sender_ip, dest_ip] = 1;
    }
}


global time_period_conn: table[addr, addr] of interval;
global prev_time_conn: table[addr, addr] of time;
global is_periodic_conn: table[addr, addr] of bool;
global total_requests_conn: table[addr, addr] of count;

event connection_reused(c: connection) {
    local sender_ip = c$id$orig_h;
    local dest_ip = c$id$resp_h;
    if ([sender_ip, dest_ip] in prev_time_conn) {
        if(is_periodic_conn[sender_ip, dest_ip]) {
            local time_int = c$start_time - prev_time_conn[sender_ip, dest_ip];
            if(!([sender_ip, dest_ip] in time_period_conn))
                time_period_conn[sender_ip, dest_ip] = time_int;
            else {
                local threshold = 1sec;
                local threshold_packets = 10;
                if (!(time_int <= time_period_conn[sender_ip, dest_ip] + threshold && time_int >= time_period_conn[sender_ip, dest_ip] - threshold))
                    if (total_requests_conn[sender_ip, dest_ip] < threshold_packets)
                        is_periodic_conn[sender_ip, dest_ip] = F;
            }
        }
        prev_time_conn[sender_ip, dest_ip] = c$start_time;
        ++total_requests_conn[sender_ip, dest_ip];
    } else {
        prev_time_conn[sender_ip, dest_ip] = c$start_time;
        is_periodic_conn[sender_ip, dest_ip] = T;
        total_requests_conn[sender_ip, dest_ip] = 1;
    }
}

event bro_done() {
    for ([i, j] in is_periodic_conn) {
        if(is_periodic_conn[i,j] && total_requests_conn[i,j] > 2) {
            local periodicity: double = |interval_to_double(time_period_conn[i,j])|;
            Log::write(LOG, [
                $source_ip=i, $destination_ip=j,
                $total_requests=total_requests_conn[i, j],
                $periodicity=periodicity]);
        }
    }
    for ([k, l] in is_periodic) {
        if(is_periodic[k,l] && total_requests[k,l] > 2) {
            periodicity = |interval_to_double(time_period[k,l])|;
            Log::write(LOG, [
                $source_ip=k, $destination_url=l,
                $total_requests=total_requests[k, l],
                $periodicity=periodicity]);
        }
    }
    for ([i, j] in is_periodic_ip) {
        if(is_periodic_ip[i,j] && total_requests_ip[i,j] > 2) {
            periodicity = |interval_to_double(time_period_ip[i,j])|;
            Log::write(LOG, [
                $source_ip=i, $destination_ip=j,
                $total_requests=total_requests_ip[i, j],
                $periodicity=periodicity]);
        }
    }
}

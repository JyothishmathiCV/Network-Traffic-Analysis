@load base/frameworks/sumstats
@load base/protocols/http
@load base/protocols/conn

type Info: record {
    src: addr &log;
    dst: string &log;
    # dst_url: string &log;
    total: count &log;
    secOrdAvg: double &log;
};



global timestamp_conn: table[addr, string] of vector of time;
# global first_order_conn: table[addr,addr] of vector of double;

redef enum Log::ID += { LOG };


event bro_init(){
	Log::create_stream(LOG, [$columns=Info, $path="heartbeattry"]);
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
    local sender_ip = c$id$orig_h;
    local dest_url = "";
    for ([index] in hlist) {
        if (hlist[index]$name == "HOST") {
            dest_url = hlist[index]$value;
        }
    }
    if (dest_url != "") {
        if ([sender_ip, dest_url] in timestamp_conn) {
		    timestamp_conn[sender_ip, dest_url][|timestamp_conn[sender_ip, dest_url]|]=c$http$ts;
        } else {
            #add timestamp_conn[sender_ip,dest_ip];
            local v:vector of time;
            timestamp_conn[sender_ip, dest_url]=v;
		    timestamp_conn[sender_ip, dest_url][|timestamp_conn[sender_ip, dest_url]|]=c$http$ts;
        }
    }
}
function calc_second_order(s: addr,d:string){
	local first_order_conn: vector of double;
	local time_stamp=timestamp_conn[s,d];
	for ( [i] in time_stamp){
		if(i!=0){
			first_order_conn[|first_order_conn|]=|(time_stamp[i]-time_stamp[i-1])|;
		}
	}
	local so: double =-1000.0;
	for([i] in first_order_conn){
		if(i!=0){
			so+=|first_order_conn[i]-first_order_conn[i-1]|;
		}
		else{
		    so=0.0;
		}
	}
	if(|first_order_conn|!=0){
	    so=so/|first_order_conn|;
	    so=so/1000;
	    local info : Info;
	    info$src=s;
	    info$dst=d;
	    info$total=|time_stamp|;
	    info$secOrdAvg=so;
	    Log::write(LOG,info);
	}
	else{
	    so=-1;
	}
	
}

event bro_done(){
	for([i,j] in timestamp_conn){
		calc_second_order(i,j);
	}
	
}

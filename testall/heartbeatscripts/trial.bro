@load base/frameworks/sumstats
@load base/protocols/http
@load base/protocols/conn

type Info: record {
    src: addr &log;
    dst: addr &log;
    # dst_url: string &log;
    total: count &log;
    secOrdAvg: double &log;
};



global timestamp_conn: table[addr, addr] of vector of double;
# global first_order_conn: table[addr,addr] of vector of double;

redef enum Log::ID += { LOG };


event bro_init(){
	Log::create_stream(LOG, [$columns=Info, $path="heartbeattry"]);
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
    local sender_ip = c$id$orig_h;
    local dest_ip = c$id$resp_h;
    if ([sender_ip, dest_ip] in timestamp_conn) {
		timestamp_conn[sender_ip, dest_ip][|timestamp_conn[sender_ip, dest_ip]|]=(|c$http$ts|);
		
        #add timestamp_conn[sender_ip,dest_ip];
        local v:vector of double;
        timestamp_conn[sender_ip, dest_ip]=v;
		timestamp_conn[sender_ip, dest_ip][|timestamp_conn[sender_ip, dest_ip]|]=(|c$http$ts|);
     }

}
function calc_second_order(s: addr,d:addr){
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
	    so = so/1000;
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
event connection_reused(c: connection) {###Checking for periodicity in connection...How is it different
    local sender_ip = c$id$orig_h;
    local dest_ip = c$id$resp_h;
	local foo = get_current_packet();
    if ([sender_ip, dest_ip] in timestamp_conn) {
		timestamp_conn[sender_ip, dest_ip][|timestamp_conn[sender_ip, dest_ip]|]=foo$ts_sec + foo$ts_usec/1000000.0;
    } else {
        #add timestamp_conn[sender_ip,dest_ip];
        local v:vector of double;
        timestamp_conn[sender_ip, dest_ip]=v;
		timestamp_conn[sender_ip, dest_ip][|timestamp_conn[sender_ip, dest_ip]|]=foo$ts_sec + foo$ts_usec/1000000.0;
    }
}


event bro_done(){
	for([i,j] in timestamp_conn){
		calc_second_order(i,j);
	}
	
}

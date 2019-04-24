module Heartbeattry;

export {
	redef enum Log::ID += {LOG};

	type Info: record {
		id: conn_id &log;
		total_number: count &log;
		periodicity: double &log;
		secondOrderAvg : double &log;
	};
}

# type payloadFreqTuple: record {
# 	payload: string;
# 	freq: count;
# };
global secondOrderVector: vector of double;
global payloadFreqTable: table[string] of count;
global payloadConnectionTable: table[string] of set[conn_id];

global payloadFreqVector: vector of payloadFreqTuple;

global freqThreshold = 500;###Why 500????

global connIdTimeTable: table[conn_id] of vector of double;

event bro_init() {
	Log::create_stream(Heartbeattry::LOG, [$columns=Info, $path="heartbeattry"]);
}

event packet_contents(c: connection, contents: string) {
	if(contents in payloadFreqTable) {
		payloadFreqTable[contents] += 1;
		add payloadConnectionTable[contents][c$id];
	}
	else {
		payloadFreqTable[contents] = 1;
		payloadConnectionTable[contents] = set();
		add payloadConnectionTable[contents][c$id];
	}

	local foo = get_current_packet();

	if(c$id in connIdTimeTable) {
		connIdTimeTable[c$id][|connIdTimeTable[c$id]|] = foo$ts_sec + foo$ts_usec/1000000.0;
	}
	else {
		connIdTimeTable[c$id] = vector();
		connIdTimeTable[c$id][0] = foo$ts_sec + foo$ts_usec/1000000.0;
	}

}

function compare(a: double, b: double): int {
	if(a < b) {
		return -1;
	}
	return 1;
}

function generateSortedVector() {
	for(i in payloadFreqTable) {
		if(payloadFreqTable[i] > freqThreshold) {
			payloadFreqVector[|payloadFreqVector|] = payloadFreqTuple($payload = i, $freq = payloadFreqTable[i]);
		}
	}
	# payloadFreqVector = sort(payloadFreqVector, compare);
}

function printRelevantData() {
  for(i in payloadFreqVector) {
    local connIds = payloadConnectionTable[payloadFreqVector[i]$payload];
	for(id in connIds) {
		local foo = connIdTimeTable[id];
		foo = sort(foo, compare);
		if(|foo| > 1) {
			# print id, |foo|,  |foo|/(foo[|foo|-1] - foo[0]);
			local info: Info;
			info$id = id;
			info$total_number = |foo|;
			info$periodicity = |foo|/(foo[|foo| - 1] - foo[0]);
			local sum: double= 0.0;
			for([index] in foo){
				if(index!=0){
					secondOrderVector[|secondOrderVector|] = foo[index]-foo[index-1];
				}
			}
			for([index] in secondOrderVector){
				if(index!=0){
					sum += secondOrderVector[index]-secondOrderVector[index-1];
				}
			}
			sum=sum/|secondOrderVector|;
			info$secondOrderAvg=sum;
			Log::write(Heartbeattry::LOG, info);
		}
	}
  }
}
# event http_header (c: connection, is_orig: bool, name: string, value: string)
# {
#     if(! is_orig) return;###Why if NOT is_origin????
#         if( c$id in Heartbeat::incomplete_reqs) 
#         {
#            local incomp = Heartbeat::incomplete_reqs[c$id];

#            local source: addr = c$id$orig_h;
#            local url: string = value + incomp$uri;

#            local comp = Heartbeat::full_http_req($source=source, $dest=c$id$resp_h, $host=value, $uri=incomp$uri, $url=url, $timestamp=c$start_time);
            
#            # print fmt("complete: %s", comp);
#            if(source in Heartbeat::last_req_time) {
#                if(url in Heartbeat::last_req_time[source]) {
#                     local diff: interval = comp$timestamp - Heartbeat::last_req_time[source][url];
#                     local obs = SumStats::Observation($dbl=interval_to_double(diff));
                    
#                }

#            }
#            # this is after so that the first request gets dropped
#            Heartbeat::append_req(source, url, comp);
#         }
#     }
# }

event new_connection(c:connection){
	if(c$id$orig_h in DNSSummary){
		if(c$id$resp_h in DNSSummary[c$id$orig_h]$dstAddr){

		}
		else{
			add DNSSummary[c$id$orig_h]$dstAddr[c$id$resp_h];
			DNSSummary[c$id$orig_h]$uniqueIpAddr+=1;
		}
	}
	# else{
	# 	local rec2: DNSRecord;
	#     rec2$srcAddr=c$id$orig_h;
	# 	add rec2$dstAddr[c$id$resp_h];
	# 	rec2$uniqueIpAddr=1;
	#     DNSSummary[c$id$orig_h]=rec2;
	# }
}

event bro_done() {
	generateSortedVector();
	printRelevantData();
}

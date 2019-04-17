module Heartbeat;

export {
	redef enum Log::ID += {LOG};

	type Info: record {
		id: conn_id &log;
		total_number: count &log;
		periodicity: double &log;
	};
}

type payloadFreqTuple: record {
	payload: string;
	freq: count;
};

global payloadFreqTable: table[string] of count;
global payloadConnectionTable: table[string] of set[conn_id];

global payloadFreqVector: vector of payloadFreqTuple;

global freqThreshold = 500;

global connIdTimeTable: table[conn_id] of vector of double;

event bro_init() {
	Log::create_stream(Heartbeat::LOG, [$columns=Info, $path="heartbeat"]);
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
			Log::write(Heartbeat::LOG, info);
		}
	}
  }
}

event bro_done() {
	generateSortedVector();
	printRelevantData();
}

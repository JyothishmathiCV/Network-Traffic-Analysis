#@load base/protocols/http
#@load base/protocols/conn
@load base/frameworks/sumstats

module Heartbeat;

export {
    ## The log ID.
    redef enum Log::ID += { LOG };

	type Info: record {
        src: string &log;
        dst_url: string &log;
        total: string &log;
        periodic: string &log;
    };

    type half_http_req: record {
        conn: connection;
        source: addr;
        uri: string;
    };

    type full_http_req: record {
        source: addr;
        dest: addr;
        host: string;
        uri: string;
        url: string;
        timestamp: time;
    };
    global incomplete_reqs: table[conn_id] of half_http_req;
    # complete requests grouped by source addr and then by url
    global complete_reqs: table[addr] of table[string] of set[full_http_req];
    global last_req_time: table[addr] of table[string] of time;

    function append_req(s: addr, u: string, r: full_http_req)
    {
        if(s in complete_reqs) {
            if(u in complete_reqs[s]) {
                add complete_reqs[s][u][r];
                last_req_time[s][u] = r$timestamp;
            }
            else {
                complete_reqs[s] = table(
                    [u] = set(r)
                );
                last_req_time[s] = table([u] = r$timestamp);
            }
        }
        else {
            complete_reqs = table(
                [s] = table([u] = set(r))
            );
            last_req_time = table(
                [s] = table ([u] = r$timestamp)
            );
        }
    }
}


event bro_init() {
    # STD_DEV also calculates average
    local r1 = SumStats::Reducer($stream="http.access_intervals", $apply=set(SumStats::STD_DEV));
    local r2 = SumStats::Reducer($stream="http.access", $apply=set(SumStats::SUM));
    Log::create_stream(LOG, [$columns=Info, $path="heartbeat2"]);
    SumStats::create([
                    $name="http.access_intervals.avg",
                    $epoch=1min,
                    $reducers=set(r1,r2),
                    $epoch_result(ts: time,key: SumStats::Key, result: SumStats::Result) = {
                        local res1 = result["http.access_intervals"];
                        local res2 = result["http.access"];
                        # print fmt("ip: %s -> url: %s avg: %.2f, stddev: %.2f, total request: %.0f", key$host, key$str, res1$average, res1$std_dev, res2$sum);
                        local periodic = fmt("%.2f s +- %.2f", res1$average, res1$std_dev);
                        Log::write(Heartbeat::LOG, [$src=fmt("%s",key$host), $dst_url=fmt("%s",key$str), $total=fmt("%.0f",res2$sum), $periodic=periodic]);
                    }
    ]);
}

module HTTP;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) 
{
    Heartbeat::incomplete_reqs[c$id] = Heartbeat::half_http_req($conn=c,$source=c$id$orig_h,$uri=original_URI);
    # print fmt("http (%s) req from: %s  to url %s : %s", method, c$id$orig_h, c$http$uri, original_URI);
}

event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(! is_orig) return;
    if (/HOST/ in name ){
        if( c$id in Heartbeat::incomplete_reqs) 
        {
           local incomp = Heartbeat::incomplete_reqs[c$id];

           local source: addr = c$id$orig_h;
           local url: string = value + incomp$uri;

           local comp = Heartbeat::full_http_req($source=source, $dest=c$id$resp_h, $host=value, $uri=incomp$uri, $url=url, $timestamp=c$start_time);
            
           # print fmt("complete: %s", comp);
           if(source in Heartbeat::last_req_time) {
               if(url in Heartbeat::last_req_time[source]) {
                    local diff: interval = comp$timestamp - Heartbeat::last_req_time[source][url];
                    local obs = SumStats::Observation($dbl=interval_to_double(diff));
                    SumStats::observe("http.access_intervals", [$host=source, $str=url], obs);
                    SumStats::observe("http.access", [$host=source, $str=url], SumStats::Observation($num=1));
               }

           }
           # this is after so that the first request gets dropped
           Heartbeat::append_req(source, url, comp);
        }
    }
}


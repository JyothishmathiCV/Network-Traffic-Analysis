@load base/frameworks/sumstats

redef enum Log::ID += { LOG };   

type DNSRecord: record {
    srcAddr:	addr &log;
    totalDnsReq: count &default = 0 &log;
    totalDnsFail: count &default = 0 &log;
	uniqueIpAddr: count &default = 0 &log;
    failureTypesDetected: set[string] &log;
    freqOfFailedReq: count &default = 0 &log;
	totalNXDomainFail: count &default = 0 &log;
	totalServFail: count &default = 0 &log;
	totalRefused: count &default = 0 &log;
	dstAddr: set[addr] &log; #Unique Destination address
	failedDomain: set[string] &log;
	passedDomain: set[string] &log;
	#freqOfNXDomainFail: double &default=0.0 &log;
};
global DNSSummary: table[addr] of DNSRecord;
event bro_init()
    {
#    local r1 = SumStats::Reducer($stream="dns.lookup", $apply=set(SumStats::UNIQUE));
#    SumStats::create([$name="dns.requests.unique",
#                      $epoch=1hrs,
#                      $reducers=set(r1),
#                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
#                        {
#                        local r = result["dns.lookup"];
#                        print fmt("%s did %d total and %d unique DNS requests in the last 1 hours.", 
#                        			key$host, r$num, r$unique);
#                        }]);

    local r2 = SumStats::Reducer($stream="DNS_Fail", $apply=set(SumStats::SUM) );

    SumStats::create([$name="variance_of_orig_bytes",
 		     $epoch=60min, 
		     $reducers=set(r2),
		     $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
			{
			    #print  fmt ("key=%s",key$host);
			    #print fmt ("result=%d",result["DNS_Fail"]$num);
			    #print result["DNS_Fail"];
			    DNSSummary[key$host]$freqOfFailedReq=result["DNS_Fail"]$num;
			    Log::write( LOG, DNSSummary[key$host]);
			}
		     #$threshold_val=(1-variance), #See note
		     #$threshold=0.9,
		     #$threshold_crossed=doNotice()#See note
		     ]);
	# local r3 = SumStats::Reducer($stream="Conn_IP", $apply=set(SumStats::SUM) );

    # SumStats::create([$name="variance_of_orig_bytes",
 	# 	     $epoch=60min, 
	# 	     $reducers=set(r3),
	# 	     $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	# 		{
	# 		    DNSSummary[key$host]$uniqueIpAddr=result["Conn_IP"]$num;
	# 		    Log::write( LOG, DNSSummary[key$host]);
	# 		}
	# 	     ]);

    Log::create_stream(LOG, [$columns=DNSRecord, $path="dnsSummary"]);
    #Log::write( LOG, "testing");

    }

event bro_done() 
	{
	    for(i in DNSSummary)
	    {
		#print i;		
		#print DNSSummary[i];
		Log::write( LOG, DNSSummary[i]);
	    }
	}



event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
#enable to demonstrate NBNS detected
#print "*********reply********";
#print c$id;
#print msg;
#print fmt ("query=%s",query);
#if ( c$id$resp_p == 53/udp)
#    print "DNS";
#else
#    print "Not DNS";
#print "******************";

    #check if IP already exists in saved records, if exists, update record. Otherwise add record
    if(c$id$orig_h in DNSSummary)
    {
	#code should be zero if no error
	if(msg$rcode==0)
	{
	    #all queries success
		if(c$id$resp_h in DNSSummary[c$id$orig_h]$dstAddr){

		}
		else{
			add DNSSummary[c$id$orig_h]$dstAddr[c$id$resp_h];
			DNSSummary[c$id$orig_h]$uniqueIpAddr+=1;
		}
	    DNSSummary[c$id$orig_h]$totalDnsReq+=msg$num_queries;
    	    add DNSSummary[c$id$orig_h]$passedDomain[query];
	}
	else
	{
	    #some queries failed
	    DNSSummary[c$id$orig_h]$totalDnsReq+=msg$num_queries;
    	    DNSSummary[c$id$orig_h]$totalDnsFail+=msg$num_queries-msg$num_answers;

	    #identify error
	    if(msg$rcode==1)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["FORMERR"];
	    else if(msg$rcode==2){
			add DNSSummary[c$id$orig_h]$failureTypesDetected["SERVFAIL"];
			DNSSummary[c$id$orig_h]$totalServFail+=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==3){
			add DNSSummary[c$id$orig_h]$failureTypesDetected["NXDOMAIN"];
			DNSSummary[c$id$orig_h]$totalNXDomainFail+=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==4)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["NOTIMP"];
	    else if(msg$rcode==5){
			add DNSSummary[c$id$orig_h]$failureTypesDetected["REFUSED"];
			DNSSummary[c$id$orig_h]$totalRefused+=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==6)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["YXDOMAIN"];
	    else if(msg$rcode==7)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["XRRSET"];
	    else if(msg$rcode==8)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["NOTAUTH"];
	    else if(msg$rcode==9)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["NOTZONE"];
	    #print fmt ("for src=%s, fail count=%d, num query=%d,num ans=%d",c$id$orig_h,DNSSummary[c$id$orig_h]$totalDnsFail,msg$num_queries,msg$num_answers);
    	    add DNSSummary[c$id$orig_h]$failedDomain[query];
	    SumStats::observe("DNS_Fail", [$host=c$id$orig_h], [$num=msg$num_queries-msg$num_answers]);
	}
	
    }
    else
    {
	#code should be zero if no error
	if(msg$rcode==0)
	{
	    #all queries success
	    local rec2: DNSRecord;
	    rec2$srcAddr=c$id$orig_h;
		add rec2$dstAddr[c$id$resp_h];
		rec2$uniqueIpAddr=1;
	    rec2$totalDnsReq=msg$num_queries;
	    rec2$totalDnsFail=0;
    	    add rec2$passedDomain[query];
	    DNSSummary[c$id$orig_h]=rec2;
	}
	else {
	    #some queries failed
	    local rec1: DNSRecord;
	    rec1$srcAddr=c$id$orig_h;
	    rec1$totalDnsReq=msg$num_queries;
    	    rec1$totalDnsFail=msg$num_queries-msg$num_answers;

	    #identify error
	    if(msg$rcode==1)
		add rec1$failureTypesDetected["FORMERR"];
	   else if(msg$rcode==2){
			add rec1$failureTypesDetected["SERVFAIL"];
			rec1$totalServFail=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==3){
			add rec1$failureTypesDetected["NXDOMAIN"];
			rec1$totalNXDomainFail=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==4)
		add rec1$failureTypesDetected["NOTIMP"];
	    else if(msg$rcode==5){
			add rec1$failureTypesDetected["REFUSED"];
			rec1$totalRefused=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==6)
		add rec1$failureTypesDetected["YXDOMAIN"];
	    else if(msg$rcode==7)
		add rec1$failureTypesDetected["XRRSET"];
	    else if(msg$rcode==8)
		add rec1$failureTypesDetected["NOTAUTH"];
	    else if(msg$rcode==9)
		add rec1$failureTypesDetected["NOTZONE"];
    	    add rec1$failedDomain[query];
	    DNSSummary[c$id$orig_h]=rec1;
	    SumStats::observe("DNS_Fail", [$host=c$id$orig_h], [$num=msg$num_queries-msg$num_answers]);
	}

    }
}
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
#print "request";
#print c$id;
    if ( c$id$resp_p == 53/udp && query != "" )
    {
        #SumStats::observe("dns.lookup", [$host=c$id$orig_h], [$str=query]);
    }
    else
    {
	#print c$id;
	#print msg;
    }
}


event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{

    #check if IP already exists in saved records, if exists, update record. Otherwise add record
    if(c$id$orig_h in DNSSummary)
    {
	#code should be zero if no error
	if(msg$rcode==0)
	{
		if(c$id$resp_h in DNSSummary[c$id$orig_h]$dstAddr){

		}
		else{
			add DNSSummary[c$id$orig_h]$dstAddr[c$id$resp_h];
			DNSSummary[c$id$orig_h]$uniqueIpAddr+=1;
		}
	    #all queries success
	    DNSSummary[c$id$orig_h]$totalDnsReq+=msg$num_queries;
    	    add DNSSummary[c$id$orig_h]$passedDomain[query];
	}
	else
	{
	    #some queries failed
	    DNSSummary[c$id$orig_h]$totalDnsReq+=msg$num_queries;
    	    DNSSummary[c$id$orig_h]$totalDnsFail+=msg$num_queries-msg$num_answers;

	    #identify error
	    if(msg$rcode==1)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["FORMERR"];
	    else if(msg$rcode==2){
			add DNSSummary[c$id$orig_h]$failureTypesDetected["SERVFAIL"];
			DNSSummary[c$id$orig_h]$totalServFail+=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==3){
			add DNSSummary[c$id$orig_h]$failureTypesDetected["NXDOMAIN"];
			DNSSummary[c$id$orig_h]$totalNXDomainFail+=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==4)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["NOTIMP"];
	    else if(msg$rcode==5){
			add DNSSummary[c$id$orig_h]$failureTypesDetected["REFUSED"];
			DNSSummary[c$id$orig_h]$totalRefused+=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==6)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["YXDOMAIN"];
	    else if(msg$rcode==7)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["XRRSET"];
	    else if(msg$rcode==8)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["NOTAUTH"];
	    else if(msg$rcode==9)
		add DNSSummary[c$id$orig_h]$failureTypesDetected["NOTZONE"];
	    #print fmt ("for src=%s, fail count=%d, num query=%d,num ans=%d",c$id$orig_h,DNSSummary[c$id$orig_h]$totalDnsFail,msg$num_queries,msg$num_answers);
    	    add DNSSummary[c$id$orig_h]$failedDomain[query];
	    SumStats::observe("DNS_Fail", [$host=c$id$orig_h], [$num=msg$num_queries-msg$num_answers]);
	}
	
    }
    else
    {
	#code should be zero if no error
	if(msg$rcode==0)
	{
	    #all queries success
	    local rec2: DNSRecord;
	    rec2$srcAddr=c$id$orig_h;
		add rec2$dstAddr[c$id$resp_h];
		rec2$uniqueIpAddr=1;
	    rec2$totalDnsReq=msg$num_queries;
	    rec2$totalDnsFail=0;
    	    add rec2$passedDomain[query];
	    DNSSummary[c$id$orig_h]=rec2;
	}
	else {
	    #some queries failed
	    local rec1: DNSRecord;
	    rec1$srcAddr=c$id$orig_h;
	    rec1$totalDnsReq=msg$num_queries;
    	    rec1$totalDnsFail=msg$num_queries-msg$num_answers;

	    #identify error
	    if(msg$rcode==1)
		add rec1$failureTypesDetected["FORMERR"];
	    else if(msg$rcode==2){
			add rec1$failureTypesDetected["SERVFAIL"];
			rec1$totalServFail=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==3){
			add rec1$failureTypesDetected["NXDOMAIN"];
			rec1$totalNXDomainFail=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==4)
		add rec1$failureTypesDetected["NOTIMP"];
	    else if(msg$rcode==5){
			add rec1$failureTypesDetected["REFUSED"];
			rec1$totalRefused=msg$num_queries-msg$num_answers;
		}
	    else if(msg$rcode==6)
		add rec1$failureTypesDetected["YXDOMAIN"];
	    else if(msg$rcode==7)
		add rec1$failureTypesDetected["XRRSET"];
	    else if(msg$rcode==8)
		add rec1$failureTypesDetected["NOTAUTH"];
	    else if(msg$rcode==9)
		add rec1$failureTypesDetected["NOTZONE"];
    	    add rec1$failedDomain[query];
	    DNSSummary[c$id$orig_h]=rec1;
	    SumStats::observe("DNS_Fail", [$host=c$id$orig_h], [$num=msg$num_queries-msg$num_answers]);
	}

    }
}

event new_connection(c:connection){
	if(c$id$orig_h in DNSSummary){
		if(c$id$resp_h in DNSSummary[c$id$orig_h]$dstAddr){

		}
		else{
			add DNSSummary[c$id$orig_h]$dstAddr[c$id$resp_h];
			DNSSummary[c$id$orig_h]$uniqueIpAddr+=1;
		}
	}
	else{
		local rec2: DNSRecord;
	    rec2$srcAddr=c$id$orig_h;
		add rec2$dstAddr[c$id$resp_h];
		rec2$uniqueIpAddr=1;
	    DNSSummary[c$id$orig_h]=rec2;
	}
}

@load base/protocols/snmp

event bro_init()
    {

    local f = Log::get_filter(SNMP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

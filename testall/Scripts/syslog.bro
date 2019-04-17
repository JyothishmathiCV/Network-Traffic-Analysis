@load base/protocols/syslog

event bro_init()
    {

    local f = Log::get_filter(Syslog::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

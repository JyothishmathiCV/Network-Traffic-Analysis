@load base/protocols/sip

event bro_init()
    {

    local f = Log::get_filter(SIP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

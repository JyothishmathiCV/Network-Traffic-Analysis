@load base/protocols/socks

event bro_init()
    {

    local f = Log::get_filter(SOCKS::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

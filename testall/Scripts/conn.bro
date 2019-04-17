

event bro_init()
    {

    local f = Log::get_filter(Conn::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

@load base/files/pe

event bro_init()
    {

    local f = Log::get_filter(PE::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

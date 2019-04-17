

event bro_init()
    {

    local f = Log::get_filter(Notice::LOG,"default");
    Log::add_filter(Conn::LOG, f); 
    }

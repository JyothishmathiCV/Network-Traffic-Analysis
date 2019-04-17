@load base/protocols/ssh

event bro_init()
    {

    local f = Log::get_filter(SSH::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

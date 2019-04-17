@load base/protocols/rdp

event bro_init()
    {

    local f = Log::get_filter(RDP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

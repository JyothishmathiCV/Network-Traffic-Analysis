@load base/protocols/ftp

event bro_init()
    {

    local f = Log::get_filter(FTP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

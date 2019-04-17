@load base/protocols/smtp

event bro_init()
    {

    local f = Log::get_filter(SMTP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    }

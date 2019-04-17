@load base/protocols/mysql

event bro_init()
    {

    local f = Log::get_filter(mysql::LOG,"default");
    Log::add_filter(Conn::LOG, f); 
    }

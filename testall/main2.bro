@load base/protocols/socks/main.bro
@load base/protocols/mysql/main.bro
@load policy/misc/loaded-scripts.bro
@load base/files/pe/main.bro
@load base/protocols/conn/main.bro
@load base/protocols/rdp/main.bro
@load base/protocols/sip/main.bro
@load base/protocols/smtp/main.bro
@load base/protocols/snmp/main.bro
@load base/protocols/ssh/main.bro
@load base/protocols/syslog/main.bro
@load base/protocols/ftp/main.bro

event bro_init()
    {
    # Replace default filter for the Conn::LOG stream in order to
    # change the log filename.

    local f = Log::get_filter(SOCKS::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    f = Log::get_filter(FTP::LOG,"default");
    Log::add_filter(Conn::LOG, f);    
    f = Log::get_filter(mysql::LOG,"default");
    Log::add_filter(Conn::LOG, f); 
    f = Log::get_filter(Notice::LOG,"default");
    Log::add_filter(Conn::LOG, f);    
    f = Log::get_filter(RDP::LOG,"default");
    Log::add_filter(Conn::LOG, f);    
    f = Log::get_filter(SSH::LOG,"default");
    Log::add_filter(Conn::LOG, f);    
    f = Log::get_filter(Syslog::LOG,"default");
    Log::add_filter(Conn::LOG, f);    
    f = Log::get_filter(Tunnel::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    f = Log::get_filter(LoadedScripts::LOG,"default");
    Log::add_filter(Conn::LOG, f);


    f = Log::get_filter(Conn::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    f = Log::get_filter(PE::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    f = Log::get_filter(RDP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    f = Log::get_filter(SIP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    f = Log::get_filter(SMTP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    f = Log::get_filter(SNMP::LOG,"default");
    Log::add_filter(Conn::LOG, f);
    f = Log::get_filter(SSH::LOG,"default");
    Log::add_filter(Conn::LOG, f);

    }


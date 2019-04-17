@load policy/misc/loaded-scripts.bro

event bro_int()
{
    local f = Log::get_filter(LoadedScripts::LOG,"default");
    Log::add_filter(Conn::LOG, f);
}

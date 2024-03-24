#include "simplomon.hh"

std::string getAgeDesc(time_t then)
{
  int diff = (time(nullptr) - then);
  if(diff < 60)
    return fmt::format("{} seconds", diff);
  else if(diff < 3600) 
    return fmt::format("{} minutes", diff/60);
  else if(diff < 2*86400) 
    return fmt::format("{:.1f} hours", diff/3600.0);

  return fmt::format("{:.1f} days", diff/86400.0);  
}

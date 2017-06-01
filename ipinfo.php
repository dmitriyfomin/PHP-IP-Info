#!/usr/bin/php
<?php

/**
* PHP IP-Info
*
* @author Dmitry Fomin
*/


/**
* Console system out println function
* @param string str
* @return string
*/
function sysout($str = "")
{
  echo $str . PHP_EOL;
}


interface IWhoisIP
{

  /**
  * Connection to WHOIS Server
  * @param string server
  * @param string ip
  * @return string
  */
  public function whois_connect($server, $ip);
}

final class IpInfo implements IWhoisIP
{

  /**
  * Show help menu
  * @return void
  */
  protected function gethelp()
  {
    sysout('---------- PHP IP-INFO -------------');
    sysout();
    sysout(' * Usage: $ php ipinfo.php 127.0.0.1');
    sysout();
    sysout('            by Dmitry Fomin, Copyright 2017');
    sysout();
  }

  /**
  * Get info about IP
  * @return void
  */
  public function getinfo()
  {
    global $argv;
    if (isset($argv[1]))
    {
      if (filter_var($argv[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false)
      {
        self::gethelp();
        $ip = str_replace('..', '.', $argv[1]);
        $host = gethostbyaddr($ip);
        $country = geoip_country_name_by_name($host);
        sysout('Hostname: ' . $host . ' (' . $country . ')');
        sysout(self::whois_connect('whois.arin.net', filter_var($argv[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)));
      } else {
        self::gethelp();
      }
    } else {
      self::gethelp();
    }
  }

  /**
  * @Override
  * Connection to WHOIS Server
  * @param string server
  * @param string ip
  * @return string
  */
  public function whois_connect($server, $ip)
  {
    if (! isset($server))
    {
      throw new \Exception('Sorry, whois server not found :(');
    } else {
      $sock = fsockopen($server, 43);
      fputs($sock, $ip."\r\n");
      $whoistext = '';
      while (! feof($sock)):
        $whoistext .= fgets($sock, 128) . PHP_EOL;
      endwhile;
      fclose($sock);
      $pattern = "|ReferralServer:  whois://([^\n<:]+)|i";
      preg_match($pattern, $whoistext, $out);
      if (! empty($out[1]))
      {
        return self::whois_connect($out[1], $ip);
      } else {
        return $whoistext;
      }
    }
  }
}

IpInfo::getinfo();

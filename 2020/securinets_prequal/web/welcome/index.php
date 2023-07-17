<?php
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);
error_reporting(0);
function check(){
  global $p;
  $arr=get_defined_functions()['internal'];
  foreach ($arr as $blacklisted) {
      if (preg_match ('/' . $blacklisted . '/im', $p)) {
          echo "Your input is blacklisted" . "<br>";
          return true;
          break;
      }
  }
  $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\\','\^','\@','\|'];
  foreach ($blacklist as $blacklisted) {
    if (preg_match('/' . $blacklisted . '/m', $p)) {
      echo "Your input is blacklisted" . "<br>";
      return true;
          break;

  return false;
}
}
}
$p = @substr($_GET['cmd'], 0, 24);
if(check()){
  die('try again');
}
else
{
  @eval($p.';');
}
<?php

error_reporting(0);
function check($str){
     $blacklist = ['[A-Zb-df-km-uw-z]',' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\$','\\','\^','~']; //allow ?cmd=1
        foreach ($blacklist as $blacklisted) {
                if (preg_match('/' . $blacklisted . '/m', $str)) {
                        header("HTTP/1.1 403 Forbidden" );
                        exit;
                }
        }
}
if(!isset($_GET['cmd'])){
    show_source(__FILE__);
}else{
        $str = $_GET['cmd'];
       
        check($str);
        eval('echo '.$str.';');
}
?>


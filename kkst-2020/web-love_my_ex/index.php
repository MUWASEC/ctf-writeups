<?php 
require_once('flag.php');

function diedump($data){
    #die(var_dump($data));
    if(is_array($data)){
        print_r($data);
        exit;
    }else{
        echo $data;
        exit;
    }

}


function parseName($ua){

    libxml_disable_entity_loader (false);
    $dom = new DOMDocument();
    $dom->loadXML($ua, LIBXML_NOENT | LIBXML_DTDLOAD);
    $x = simplexml_import_dom($dom);
    $name = $x->name;
    diedump($name);

}

if(isset($_POST['input'])){
    #echo $_POST['input'];
    #exit;
    $f = filter($_POST['input']);
    #echo $f;
    parseName($f);

}else{

    highlight_file(__FILE__);
    parseName($example);
}

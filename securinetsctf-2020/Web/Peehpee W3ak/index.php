<?php
//Config
require("flag.php");
highlight_file(__FILE__);
//Get Vars
if(isset($_GET['kahla']) && isset($_GET['securinets'])){
    $a=$_GET['kahla'];
    $b=$_GET['securinets'];
}
//Enough comments xd
if ($a==$b){
die("Wait ! kahla and securinets cant be the same :(");
}
if (sha1($a)===sha1($b)){
print("Woow how did you solve it :o\n");
echo $flag;
}
?>

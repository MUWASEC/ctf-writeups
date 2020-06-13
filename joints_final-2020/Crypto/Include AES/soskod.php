<?php 

  $ENCRYPTIONKEY = "<<REDACTED>>";
  $IV            = "<<REDACTED>>";

    function enc($data,$key,$iv){

        $encrypted = openssl_encrypt($data, 'aes-128-cbc', $key, 0, $iv);
        $encrypted = $iv.base64_decode($encrypted);
        return md5($encrypted).bin2hex($encrypted);
    }

    function dec($encryptedData,$key,$iv){
      $decrypted=openssl_decrypt(base64_encode($encryptedData), 'aes-128-cbc', $key, 0, $iv);
      return $decrypted;
    }

    function filter($param){
      if (strpos($param, '.') !== false || strpos($param, ':') !== false){
        die('hekel detected !!') ;
      } 
      if (strpos($param, 'index')!== false) {
        include 'home.php';
      }

    }

    function pad($message){
      if (strlen($message) % 8) {
        $message = str_pad($message,
        strlen($message) + 8 - strlen($message) % 8, 8-strlen($message) % 8);
        return $message;
      }else{
        return $message;
      }
    }

    function unpad($message){   
      if(is_numeric(substr($message, -1))){
        return str_replace(substr($message, -1),"",$message);
      }else{
        return $message;        
      }  
    }
    
    if(!empty($_GET['page'])){
 
      $page=hex2bin(substr($_GET['page'],32));
      $hash=substr($_GET['page'],0,32);

      if ($hash!==md5($page)){
         die("An error occurred while verifying MD5 !!!");
      }

      $iv=substr($page,0,16);
      $data=substr($page,16);   

      $decData=dec($data,$ENCRYPTIONKEY,$iv);
      $decData=unpad($decData);
      filter($decData);

      if((@include "./".$decData.".php") === false)
      {
        echo "An error occurred while including  ".$decData;
      }  

    }else{
        include 'home.php';
    }

?>
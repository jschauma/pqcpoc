<?php
$LOGFILE = "/var/log/pqcpoc";
$NAMED_GROUP = $_SERVER['SSL_CURVE'];
$PROTOCOL= $_SERVER['SSL_PROTOCOL'];
$CIPHER = $_SERVER['SSL_CIPHER'];
$HTTP = $_SERVER['SERVER_PROTOCOL'];

file_put_contents($LOGFILE, date("c") . " " .
        $_SERVER['REMOTE_ADDR'] . " \"" .
        $_SERVER['REQUEST_METHOD'] . " " .
        $_SERVER['REQUEST_URI'] . " " .
        $_SERVER['SERVER_PROTOCOL'] . "\" " .
        "$PROTOCOL $CIPHER $NAMED_GROUP\n",
        FILE_APPEND);

?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta http-equiv="content-type" content= "text/html; charset=utf-8">
    <title>PQC PoC</title>
  </head>
  <body>
    <h1>PQC PoC</h1>
    <hr class="noshade" style="width:100%;">
    <p>
      This site uses: OpenSSL 3.5; <?php echo $_SERVER['SERVER_SOFTWARE']; ?>
    </p>
    <hr class="noshade" style="width:100%;">
    <p>
      You appear to be using:
    </p>
    <p>
<?php
	echo "        HTTP Version: {$HTTP}<br>\n";
	echo "        Protocol: {$PROTOCOL}<br>\n";
	echo "        Cipher: {$CIPHER}<br>\n";
	echo "        Named Group: {$NAMED_GROUP}<br>\n";
?>
    </p>
    <hr class="noshade" style="width:100%;">
   <p>
      Also available:
      <ul>
	<li><a href="https://boringssl-nginx.pqc.dotwtf.wtf">https://boringssl-nginx.pqc.dotwtf.wtf</a></li>
	<li><a href="https://golang.pqc.dotwtf.wtf">https://golang.pqc.dotwtf.wtf</a></li>
        <li><a href="https://java-bc.pqc.dotwtf.wtf">https://java-bc.pqc.dotwtf.wtf</a></li>
        <li><a href="https://openssl-oqs-apache.pqc.dotwtf.wtf">https://openssl-oqs-apache.pqc.dotwtf.wtf</a></li>
        <li><a href="https://wolfssl-nginx.pqc.dotwtf.wtf">https://wolfssl-nginx.pqc.dotwtf.wtf</a></li>
      </ul>
    </p>
    <hr class="noshade" style="width:100%;">
    <small>
    [<a href="https://www.netmeister.org/">homepage</a>]&nbsp;
    [<a href="mailto:jschauma@netmeister.org">jschauma@netmeister.org</a>]&nbsp;
    [<a href="https://mstdn.social/@jschauma/">@jschauma</a>]&nbsp;
    </small>
    <hr class="noshade" style="width:100%;">
  </body>
</html>

<?php

/*************************************************************************************
  File which provides our Open ID Connect functionality. Written for Google
  but should be fairly generic for other connect providers. The goal is to
  be simple, 1 file with minimal overhead.
  Thankyou for clear docs: https://connect2id.com/learn/openid-connect.

  Also required is JWT RFC (used in function decodejwt):
  JWK (JSON Web Key)
  https://www.rfc-editor.org/rfc/rfc7515.txt
  and
  JWS (JSON Web Signiture)
  https://tools.ietf.org/html/rfc7517
  and
  JSON Web Algorithms (JWA)
  https://tools.ietf.org/html/rfc7518
  and
  JWT (JSON Web Token)
  https://tools.ietf.org/html/rfc7519

  Requires GOOGLE_OPENIDCONNECT_CLIENTID, GOOGLE_OPENIDCONNECT_CLIENTSECRET and
  GOOGLE_OPENIDCONNECT_REDIRECTURL to be defined.

  Nick Knight 04.01.2019
  Hannah Knight 01.09.2020 - added support for NHS, key conversion and improved security.
*/

/*************************************************************************************
  Function: googlediscovery/ nhsstaffdiscovery
  Purpose: Get the URL endpoints from the discovery document.

  The general discovery() function gets the URL endpoints from the discovery document
  and all the public keys. It then puts these into the $_SESSION super global. This 
  function is called in all cases.

  The specific googlediscovery()/ nhsstaffdiscovery() functions save global variables
  which are used later in the file.

  References:
  https://developers.google.com/identity/protocols/OpenIDConnect#discovery
*************************************************************************************/
function discovery ( $openiddocurl) {

  // one function that inserts jti into database and deletes expired jtis
  require("accessjtidatabase.php");
  $_SESSION[ "jti" ] = bin2hex(random_bytes(32));
  discoverjti( );

  $_SESSION[ "openid_document" ] = json_decode(
    file_get_contents( $openiddocurl ),
    true
  );

  $pkis = json_decode(
    file_get_contents($_SESSION[ "openid_document" ][ "jwks_uri" ]),
    true
  );

    /*
    store resulting key id into "pubkey" dict as dict key, value will be the PEM certificate
    */
  $_SESSION[ "pubkey" ] = array();
  foreach( $pkis[ "keys" ] as $pki )
  {
    $_SESSION[ "pubkey" ][ $pki[ "kid" ] ] = jwkstopublicpem( $pki );
  }

}



function googlediscovery()
{
  discovery("https://accounts.google.com/.well-known/openid-configuration");

  $_SESSION[ "clientsecret" ] = GOOGLE_OPENIDCONNECT_CLIENTSECRET; // function called define means you can define fixed values to strings/ variables
  $_SESSION["desktopredirectvar"] = urlencode( GOOGLE_OPENIDCONNECT_DESKTOPREDIRECTURL );
  $_SESSION["generalredirectvar"] = urlencode( GOOGLE_OPENIDCONNECT_REDIRECTURL );
  $_SESSION["client_id"] = urlencode( GOOGLE_OPENIDCONNECT_CLIENTID );
  $_SESSION["scope"] = "openid%20profile%20email";
  $_SESSION[ "client_assertion_type" ] = "";
  $_SESSION[ "client_assertion" ] = "";
  $_SESSION[ "authorization" ] = "Basic " . base64_encode( GOOGLE_OPENIDCONNECT_CLIENTID .
                                                  ":" .
                                                  GOOGLE_OPENIDCONNECT_CLIENTSECRET
                                              );
  $_SESSION[ "private_key" ] = "";

}

function nhspatientdiscovery()
{
  discovery("https://auth.sandpit.signin.nhs.uk/.well-known/openid-configuration");

  $_SESSION[ "clientsecret" ] = "";
  $_SESSION["desktopredirectvar"] = urlencode("http://localhost:8000/completeauth.php"); // what will this be replaced with?
  $_SESSION["generalredirectvar"] = urlencode("http://localhost:8000/completeauth.php");
  $_SESSION["client_id"] = ISSNAME;
  $_SESSION["scope"] = "openid%20profile%20email%20phone%20gp_registration_details%20gp_integration_credentials%20client_metadata";
  $_SESSION[ "client_assertion_type" ] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  $_SESSION[ "authorization" ] = "";
  $_SESSION[ "private_key" ] = openssl_pkey_get_private( NHSPRVATEKEY );
  $_SESSION[ "client_assertion" ] = encodejwt();

}

/*************************************************************************************
  Function: step1a - named after the step outlined in the document
  https://connect2id.com/learn/openid-connect - which differs slightly in
  step numbers in the Google doc. This grabs the Google dicovery document then
  generates a state code and redirects the user to auth via Google.

  Redirects user to whatever login service is being used.
*************************************************************************************/
function step1a( $of = "" )
{
  $_SESSION[ "openid_state" ] = sha1( openssl_random_pseudo_bytes( 1024 ) ); // anti-forgery state token

  $url = $_SESSION[ "openid_document" ][ "authorization_endpoint" ] . // COMMON TO BOTH
      "?response_type=code" .
      "&scope=" . $_SESSION["scope"] .
      "&client_id=" . $_SESSION["client_id"] .
      "&state=" . $_SESSION[ "openid_state" ];


  // redirecting user
  // if the user is using bv desktop...
  if( FALSE !== strpos( $_SERVER['HTTP_USER_AGENT'], "bvDesktopWindows" ) )
  {
    $url .= "&redirect_uri=" . $_SESSION["desktopredirectvar"];
    if( "json" == $of )
    {
      api_return_json( array( "url" => $url ) );
    }

    echo '<!DOCTYPE html><html lang="en"><script type="text/javascript">',
           'winAuth( "' . $url . '", function( path ){ window.location.href = "https://www.babblevoice.com" + path.replace(/%20/g,"+") } )',
          '</script></head><body><h1>Please wait - a browser should open to login with.</h1></body></html>';
  }
  else // if the user is using bv in a normal browser...
  {
    $url .= "&redirect_uri=" . $_SESSION["generalredirectvar"];
    if( "json" == $of )
    {
      // html level
      api_return_json( array( "url" => $url ) ); // browser can request for redirect in json format
    }
    // This will send a 302 redirect
    // http level
    header( "Location: " . $url ); // or the browser will redirect manually
    // echo $url;
  }

  exit;
}

/*************************************************************************************
  Function: step1b - named after the step outlined in the document
  https://connect2id.com/learn/openid-connect - which differs slightly in
  step numbers in the Google doc. step1a completed and directed the user
  in his/her browser to Google to authenticate. The user has arrived back here
  with a code and state. The state we must verify and then we can act on the
  the code which is an intermediate token.

  Google case: 
    Verify anti-forgery state token. Go onto step2().

  NHSpatient case:
    Send a JWT signed with our private key.
*************************************************************************************/
function step1b()
// verifying the anti-forgery state token
{

  $code = $_GET[ "code" ];
  $state = $_GET[ "state" ];

  // using hash equals ensures full security
  if( hash_equals( $state, $_SESSION[ "openid_state" ] ) )
  {
    return step2( $code );
  }
  return FALSE;
}

/*************************************************************************************
  Function: step2 - named after the step outlined in the document
  https://connect2id.com/learn/openid-connect - which differs slightly in
  step numbers in the Google doc. step1 completed and directed the user
  in his/her browser to Google to authenticate. Step 2 swap the code for
  a token. Currently supported basic authentication. JWT not supported.
*************************************************************************************/
function step2( $code, $provider="NHSstaff" )
{
  $url = $_SESSION[ "openid_document" ][ "token_endpoint" ];

  $postdata = "grant_type=authorization_code" .
              "&code=" . $code . 
              "&client_id=" . $_SESSION[ "client_id" ] . 
              "&client_assertion_type=" . $_SESSION[ "client_assertion_type" ] . 
              "&client_assertion=" . $_SESSION[ "client_assertion" ]
              ;
  
  if( FALSE !== strpos( $_SERVER['HTTP_USER_AGENT'], "bvDesktopWindows" ) )
  {
    $postdata .= "&redirect_uri=" . $_SESSION["desktopredirectvar"];
  }
  else
  {
    $postdata .= "&redirect_uri=" . $_SESSION["generalredirectvar"];
  }


  $ch = curl_init( $url );
  curl_setopt( $ch, CURLOPT_POST, 1 );
  curl_setopt( $ch, CURLOPT_POSTFIELDS, $postdata );
  curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
  curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, 1 );
  curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 2 );
  curl_setopt( $ch, CURLOPT_FORBID_REUSE, 1 );

  curl_setopt( $ch, CURLOPT_HTTPHEADER, array(
      "Content-Type: application/x-www-form-urlencoded",
      "Authorization: " . $_SESSION[ "authorization" ],
      "Connection: Close"
    )
  );
  

  $result = curl_exec( $ch );
  $jsonobj = json_decode( $result, true );

  // $jsonobj also contatcs access_token.
  if( !array_key_exists( "id_token", $jsonobj) )
  {
    echo "There be bad things here";
    die();
  }

  return decodejwt( $jsonobj[ "id_token" ], $_SESSION[ "clientsecret" ] );

}

/*************************************************************************************
  Function: base64url_decode - user contributed notes from base64_decode - thank you.
*************************************************************************************/
function base64url_decode( $data )
{
  $data = strtr( $data, '-_', '+/');
  $data .= str_repeat('=', 3 - ( 3 + strlen( $data ) ) % 4 );

  return base64_decode( $data );
}

/*************************************************************************************
  Function: base64url_encode - user contributed notes from base64_encode - thank you.
*************************************************************************************/
function base64url_encode( $data )
{
  return rtrim( strtr( base64_encode( $data ), '+/', '-_'), '=');
}

/*************************************************************************************
  Function: PHP < 5.4.0 doesn't include hash_equals which is required for safe
  checking of hashes. This function comes from
  http://php.net/manual/en/function.hash-equals.php user contributed content - thank
  you.
*************************************************************************************/
if( !function_exists( "hash_equals" ) )
{
  function hash_equals( $str1, $str2 )
  {
    if( strlen( $str1 ) != strlen( $str2 ) )
    {
      return false;
    }
    else
    {
      $res = $str1 ^ $str2;
      $ret = 0;
      for( $i = strlen( $res ) - 1; $i >= 0; $i--) $ret |= ord( $res[ $i ] );
      return !$ret;
    }
  }
}


/*************************************************************************************
  Function: encodejwtnhs - encodes a jwt for step 2. NB: this is only required for 
  NHS Login and the jwt is structured according to NHS Login documentation. Therefore,
  another function will need to be made for other login services.

  Currently only supporting alg HS256.

  Reference: https://developer.okta.com/blog/2019/02/04/create-and-verify-jwts-in-php
*************************************************************************************/
function encodejwt( )
{
  // 1. the header
  // contains information about how the JWT signature should be computed
  $jwtheader = base64url_encode(json_encode(array(
    "alg" => "RS512",
    "typ" => "JWT"
  )));


  // 2. Finds the expirary date to be used in the jwt
  // expirary date is set to be 1 hour from now
  // time needs to be in NumericDate format for a jwt
  date_default_timezone_set(date_default_timezone_get());
  $currenttime = (strtotime(date('m/d/Y h:i:s a', time())));
  $expdate = $currenttime + 3600;

  // 3. the unisgned jwt
  // contains information about the user that’s stored inside the JWT
  // (also referred to as ‘claims’ of the JWT).
  $jwtpayload = base64url_encode(json_encode(array(
    "iss" => ISSNAME,
    "sub" => SUBNAME,
    "aud" => $_SESSION[ "openid_document" ][ "token_endpoint" ], // token endpoint url
    "exp" => $expdate,
    "jti" => $_SESSION[ "jti" ] // shows that it is a new jwt since the jti is new each time
  )));

  // 4. combine
  $headerpayload = $jwtheader . "." . $jwtpayload ;

  // 4. sign with private key
  if (TRUE === openssl_sign ( $headerpayload, $signature , $_SESSION[ "private_key" ], OPENSSL_ALGO_SHA512 )) {
    return $headerpayload . "." . base64url_encode($signature);
  }

  return FALSE;

}


/*************************************************************************************
  Function: decodejwt - simple implimentation to decode a JWT and verify it.
  Currently only supporting alg HS256.
*************************************************************************************/
function decodejwt( $input, $key="" )
{
  // makes the variables $head64, $body64 and $crypto64 which are the encoded parts
  // of the jwt
  list( $headb64, $bodyb64, $cryptob64 ) = explode( ".", $input );
  $msg = $headb64 . "." . $bodyb64;

  // decodes the head and the body
  $head = base64_decode( $headb64 );
  $body = base64_decode( $bodyb64 );


  /*
    Example:
    $head =
    {"typ":"JWT",
      "alg":"HS256"}
  */
  $jwtheader = json_decode( $head, true );
  $jwtbody = json_decode( $body, true );
  if( "JWT" != $jwtheader[ "typ" ] )
  {
    return;
  }

  // checks if jti has already been used
  require("accessjtidatabase.php");
  queryjti ( $jwtheader[ "jti" ] );
  queryjti ( $jwtbody[ "jti" ] );

  switch( $jwtheader[ "alg" ] )
  {
    case "HS256":
    {
      $decoded = hash_hmac( "SHA256", $msg, $key, TRUE );
      if( hash_equals( base64url_encode( $decoded ), $cryptob64 ) )
      {
        return json_decode( $body, TRUE );
      }
      break;
    }
    case "HS384":
    {
      $decoded = hash_hmac( "SHA384", $msg, $key, TRUE );
      if( hash_equals( base64url_encode( $decoded ), $cryptob64 ) )
      {
        return json_decode( $body, TRUE );
      }
      break;
    }
    case "HS512":
    {
      $decoded = hash_hmac( "SHA512", $msg, $key, TRUE );
      if( hash_equals( base64url_encode( $decoded ), $cryptob64 ) )
      {
        return json_decode( $body, TRUE );
      }
      break;
    }
    case "RS256":
    {
      $k = $_SESSION[ "pubkey" ][ $jwtheader[ "kid" ] ];
      if( 1 === openssl_verify( $msg, base64url_decode( $cryptob64 ), $k, OPENSSL_ALGO_SHA256 ) )
      {
        openssl_x509_free( $k );
        return json_decode( $body, TRUE );
      }
      break;
    }

    case "RS384":
    {
      $k = $_SESSION[ "pubkey" ][ $jwtheader[ "kid" ] ];
      if( 1 === openssl_verify( $msg, base64url_decode( $cryptob64 ), $k, OPENSSL_ALGO_SHA384  ) )
      {
        openssl_x509_free( $k );
        return json_decode( $body, TRUE );
      }
      break;
    }
    case "RS512":
    {
      $k = $_SESSION[ "pubkey" ][ $jwtheader[ "kid" ] ];
      if( 1 === openssl_verify( $msg, base64url_decode( $cryptob64 ), $k, OPENSSL_ALGO_SHA512  ) )
      {
        return json_decode( $body, TRUE );
      }
      break;
    }
    default:
    {
      error_log( "Open id connect returned a hash we don't know about (" . $jwtheader[ "alg" ] . ")." );
    }
  }

  return FALSE;
}

/*************************************************************************************
  This function is now used for Google and NHS Login (although another method was used
  in the previous functions for Google).
*************************************************************************************/
function jwkstopublicpem ($jwk)
{
  // base64url decode the exponent and modulus
  $exponent = base64url_decode($jwk[ "e" ]);
  $modulus = base64url_decode($jwk[ "n" ]);

  // note the 257 byte offset to skip the leading zero byte of 65537!

  // create the header by base64 decoding the following string 
  $header = base64_decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA");

  // create the mid-header by converting "02 03" to binary
  $midheader = sprintf("%c%c", 2, 3 );

  // Concatenate them together
  $binarydata = $header . $modulus . $midheader . $exponent;
  
  // convert this to PEM file
  $pemkey = der2pem($binarydata);

  return $pemkey;
  
}

function der2pem($der_data) {
  $pem = chunk_split(base64_encode($der_data), 64, "\n");
  $pem = "-----BEGIN PUBLIC KEY-----\n".$pem."-----END PUBLIC KEY-----\n";
  return $pem;
}

<?php

// single function that does all of the database work for the discovery function in openid.php
function discoverjti( )
{
    $db = sqliteopen( );
    insertjti( $db );
    deleteexpiredjtis( $db );
    sqliteclose( $db );
}

// open database
function sqliteopen( )
{
    $handle = new SQLite3( './phpsqlite.db' );
    // create table if not exists
    $query = 'CREATE TABLE IF NOT EXISTS jtis (
        jti_id TEXT PRIMARY KEY NOT NULL UNIQUE,
        date_created INTEGER NOT NULL UNIQUE
    )';
    $handle->exec( $query );
    return $handle;
}

// closes the database
function sqliteclose( $db )
{
    $db->close( );
}

// check a jti exists
// returns if jti doesn't exist in the database
// dies if jti already exists
// NB: THIS ASSUMES THERE WILL NOT BE MORE THAN 1 ENTRY FOR THE SAME JTI
function queryjti ( $jti )
{
    $db = sqliteopen( );

    $stmt = $db->prepare('SELECT count(*) FROM jtis WHERE jti_id =:jti;');
    $stmt->bindValue(':jti', $jti, SQLITE3_TEXT);
    $result = $stmt->execute()->fetchArray()[0];
    $stmt->close();

    sqliteclose( $db );

    if ($result === 0)
    {
        return;
    }

    else
    {
        header("HTTP/1.1 500 Bad things happened");
        die();
    }
}

// insert jti to database
function insertjti( $dbhandle )
{
    $date_now = (strtotime(date('m/d/Y h:i:s a', time())));
    $stmt = $dbhandle->prepare('INSERT INTO jtis(jti_id,date_created) VALUES(:jti,:date_now);');
    $stmt->bindValue(':jti', $_SESSION[ "jti" ], SQLITE3_TEXT);
    $stmt->bindValue(':date_now', $date_now, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $stmt->close();
    //print_r($result);
    return $result;
}

// delete jtis that are older than a month from database
function deleteexpiredjtis( $dbhandle ) {

    $query = 'DELETE FROM jtis WHERE date_created >= datetime("now", "-1 month")';
    $result = $dbhandle->exec( $query );

    return $result;
}


?>

<?php
/**
 * @file
 * Replaces Drupal's session handling functions.
 */

/**
 * Session handler assigned by session_set_save_handler().
 *
 * This function is used to handle any initialization, such as file paths or
 * database connections, that is needed before accessing session data. Drupal
 * does not need to initialize anything in this function.
 *
 * This function should not be called directly.
 *
 * @return
 *   This function will always return TRUE.
 */
function _drupal_session_open() {
  return TRUE;
}

/**
 * Session handler assigned by session_set_save_handler().
 *
 * This function is used to close the current session. Because Drupal stores
 * session data in the database immediately on write, this function does
 * not need to do anything.
 *
 * This function should not be called directly.
 *
 * @return
 *   This function will always return TRUE.
 */
function _drupal_session_close() {
  return TRUE;
}

/**
 * Session handler assigned by session_set_save_handler().
 *
 * This function will be called by PHP to retrieve the current user's
 * session data, which is stored in the database. It also loads the
 * current user's appropriate roles into the user object.
 *
 * This function should not be called directly. Session data should
 * instead be accessed via the $_SESSION superglobal.
 *
 * @param $sid
 *   Session ID.
 *
 * @return
 *   Either an array of the session data, or an empty string, if no data
 *   was found or the user is anonymous.
 */
function _drupal_session_read($sid) {
  global $user, $is_https;

  // Handle the case of first time visitors and clients that don't store
  // cookies (eg. web crawlers).
  $insecure_session_name = substr(ini_get('session.name'), 1);
  if (!isset($_COOKIE[ini_get('session.name')]) && !isset($_COOKIE[$insecure_session_name])) {
    $user = drupal_anonymous_user();
    return '';
  }

  // Otherwise, if the session is still active, we have a record of the
  // client's session in the database. If it's HTTPS then we are either have
  // a HTTPS session or we are about to log in so we check the sessions table
  // for an anonymous session with the non-HTTPS-only cookie.
  if ($is_https) {
    $user = db_query("SELECT u.*, s.* FROM {users} u INNER JOIN {sessions} s ON u.uid = s.uid WHERE s.ssid = :ssid", array(':ssid' => $sid))->fetchObject();
    if (!$user) {
      if (isset($_COOKIE[$insecure_session_name])) {
        $user = db_query("SELECT u.*, s.* FROM {users} u INNER JOIN {sessions} s ON u.uid = s.uid WHERE s.sid = :sid AND s.uid = 0", array(
        ':sid' => $_COOKIE[$insecure_session_name]))
        ->fetchObject();
      }
    }
  }
  else {
    $user = db_query("SELECT u.*, s.* FROM {users} u INNER JOIN {sessions} s ON u.uid = s.uid WHERE s.sid = :sid", array(':sid' => $sid))->fetchObject();
  }

  // We found the client's session record and they are an authenticated,
  // active user.
  if ($user && $user->uid > 0 && $user->status == 1) {
    // This is done to unserialize the data member of $user.
    $user->data = unserialize($user->data);

    // Add roles element to $user.
    $user->roles = array();
    $user->roles[DRUPAL_AUTHENTICATED_RID] = 'authenticated user';
    $user->roles += db_query("SELECT r.rid, r.name FROM {role} r INNER JOIN {users_roles} ur ON ur.rid = r.rid WHERE ur.uid = :uid", array(':uid' => $user->uid))->fetchAllKeyed(0, 1);
  }
  elseif ($user) {
    // The user is anonymous or blocked. Only preserve two fields from the
    // {sessions} table.
    $account = drupal_anonymous_user();
    $account->session = $user->session;
    $account->timestamp = $user->timestamp;
    $user = $account;
  }
  else {
    // The session has expired.
    $user = drupal_anonymous_user();
    $user->session = '';
  }

  // Store the session that was read for comparison in _drupal_session_write().
  $last_read = &drupal_static('drupal_session_last_read');
  $last_read = array(
    'sid' => $sid,
    'value' => $user->session,
  );

  return $user->session;
}

/**
 * Session handler assigned by session_set_save_handler().
 *
 * This function will be called by PHP to store the current user's
 * session, which Drupal saves to the database.
 *
 * This function should not be called directly. Session data should
 * instead be accessed via the $_SESSION superglobal.
 *
 * @param $sid
 *   Session ID.
 * @param $value
 *   Serialized array of the session data.
 *
 * @return
 *   This function will always return TRUE.
 */
function _drupal_session_write($sid, $value) {
  global $user, $is_https;

  // The exception handler is not active at this point, so we need to do it
  // manually.
  try {
    if (!drupal_save_session()) {
      // We don't have anything to do if we are not allowed to save the session.
      return;
    }

    // Check whether $_SESSION has been changed in this request.
    $last_read = &drupal_static('drupal_session_last_read');
    $is_changed = !isset($last_read) || $last_read['sid'] != $sid || $last_read['value'] !== $value;

    // For performance reasons, do not update the sessions table, unless
    // $_SESSION has changed or more than 180 has passed since the last update.
    if ($is_changed || REQUEST_TIME - $user->timestamp > variable_get('session_write_interval', 180)) {
      // Either ssid or sid or both will be added from $key below.
      $fields = array(
        'uid' => $user->uid,
        'cache' => isset($user->cache) ? $user->cache : 0,
        'hostname' => ip_address(),
        'session' => $value,
        'timestamp' => REQUEST_TIME,
      );

      // Use the session ID as 'sid' and an empty string as 'ssid' by default.
      // _drupal_session_read() does not allow empty strings so that's a safe
      // default.
      $key = array('sid' => $sid, 'ssid' => '');
      // On HTTPS connections, use the session ID as both 'sid' and 'ssid'.
      if ($is_https) {
        $key['ssid'] = $sid;
        // The "secure pages" setting allows a site to simultaneously use both
        // secure and insecure session cookies. If enabled and both cookies are
        // presented then use both keys.
        if (variable_get('https', FALSE)) {
          $insecure_session_name = substr(ini_get('session.name'), 1);
          if (isset($_COOKIE[$insecure_session_name])) {
            $key['sid'] = $_COOKIE[$insecure_session_name];
          }
        }
      }

      db_merge('sessions')
        ->key($key)
        ->fields($fields)
        ->execute();
    }

    // Likewise, do not update access time more than once per 180 seconds.
    if ($user->uid && REQUEST_TIME - $user->access > variable_get('session_write_interval', 180)) {
      db_update('users')
        ->fields(array(
          'access' => REQUEST_TIME
        ))
        ->condition('uid', $user->uid)
        ->execute();
    }

    return TRUE;
  }
  catch (Exception $exception) {
    require_once DRUPAL_ROOT . '/includes/errors.inc';
    // If we are displaying errors, then do so with no possibility of a further
    // uncaught exception being thrown.
    if (error_displayable()) {
      print '<h1>Uncaught exception thrown in session handler.</h1>';
      print '<p>' . _drupal_render_exception_safe($exception) . '</p><hr />';
    }
    return FALSE;
  }
}

/**
 * Initializes the session handler, starting a session if needed.
 */
function drupal_session_initialize() {
  global $user;
  if (!empty($_COOKIE[ini_get('session.name')]) || ($is_https && variable_get('https', FALSE) && !empty($_COOKIE[substr(ini_get('session.name'), 1)]))) {
    // If a session cookie exists, initialize the session. Otherwise the
    // session is only started on demand in drupal_session_commit(), making
    // anonymous users not use a session cookie unless something is stored in
    // $_SESSION. This allows HTTP proxies to cache anonymous pageviews.
    $_SESSION->start();
    if (!empty($user->uid) || !empty($_SESSION)) {
      drupal_page_is_cacheable(FALSE);
    }
  }
  else {
    // Set a session identifier for this request. This is necessary because
    // we lazily start sessions at the end of this request, and some
    // processes (like drupal_get_token()) needs to know the future
    // session ID in advance.
    $user = drupal_anonymous_user();
  }
  date_default_timezone_set(drupal_get_user_timezone());
}

/**
 * Forcefully starts a session, preserving already set session data.
 *
 * @ingroup php_wrappers
 */
function drupal_session_start() {
  // Command line clients do not support cookies nor sessions.
  if (!drupal_session_started() && !drupal_is_cli()) {
    // Save current session data before starting it, as PHP will destroy it.
    $session_data = isset($_SESSION) ? $_SESSION : NULL;

    $_SESSION->start();
    drupal_session_started(TRUE);

    // Restore session data.
    if (!empty($session_data)) {
      $_SESSION += $session_data;
    }
  }
}

/**
 * Commits the current session, if necessary.
 *
 * If an anonymous user already have an empty session, destroy it.
 */
function drupal_session_commit() {
  global $user;

  if (!drupal_save_session()) {
    // We don't have anything to do if we are not allowed to save the session.
    return;
  }

  if (empty($user->uid) && empty($_SESSION)) {
    // There is no session data to store, destroy the session if it was
    // previously started.
    if (drupal_session_started()) {
      $_SESSION->destroy();
    }
  }
  else {
    // There is session data to store. Start the session if it is not already
    // started.
    if (!drupal_session_started()) {
      drupal_session_start();
    }
    $_SESSION->save();
  }
}

/**
 * Returns whether a session has been started.
 */
function drupal_session_started($set = NULL) {
  static $session_started = FALSE;
  if (isset($set)) {
    $session_started = $set;
  }
  return $session_started && session_id();
}

/**
 * Called when an anonymous user becomes authenticated or vice-versa.
 *
 * @ingroup php_wrappers
 */
function drupal_session_regenerate() {
  global $user, $is_https;

  if (drupal_session_started()) {
    $old_session_id = $_SESSION->getId();
  }

  if (isset($old_session_id)) {
    drupal_session_destroy_uid($user->uid);
    drupal_session_start();
  }
  else {
    // Start the session when it doesn't exist yet.
    // Preserve the logged in user, as it will be reset to anonymous
    // by _drupal_session_read.
    drupal_session_start();
  }
  date_default_timezone_set(drupal_get_user_timezone());
}

/**
 * Session handler assigned by session_set_save_handler().
 *
 * Cleans up a specific session.
 *
 * @param $sid
 *   Session ID.
 */
function _drupal_session_destroy($sid) {
  global $user;
  $_SESSION->destroy();
  $user = drupal_anonymous_user();
}

/**
 * Determines whether to save session data of the current request.
 *
 * This function allows the caller to temporarily disable writing of
 * session data, should the request end while performing potentially
 * dangerous operations, such as manipulating the global $user object.
 * See http://drupal.org/node/218104 for usage.
 *
 * @param $status
 *   Disables writing of session data when FALSE, (re-)enables
 *   writing when TRUE.
 *
 * @return
 *   FALSE if writing session data has been disabled. Otherwise, TRUE.
 */
function drupal_save_session($status = NULL) {
  $save_session = &drupal_static(__FUNCTION__, TRUE);
  if (isset($status)) {
    $save_session = $status;
  }
  return $save_session;
}

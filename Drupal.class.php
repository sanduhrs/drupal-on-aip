<?php
/**
 * @file
 * AiP handler for Drupal
 */

/**
 * Root directory of Drupal installation.
 */
define('DRUPAL_ROOT', getcwd());

require_once DRUPAL_ROOT . '/includes/bootstrap.inc';

class Drupal {

    public function __construct() {
      $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
      $_SERVER['SERVER_SOFTWARE'] = 'appserver-in-php';
      $_SERVER['PHP_SELF'] = basename(__FILE__);
      drupal_bootstrap(DRUPAL_BOOTSTRAP_FULL);
    }

    public function __invoke($context) {
      //$GLOBALS['user'] = drupal_anonymous_user();
      $GLOBALS['user'] = user_load(1);
      unset($GLOBALS['theme']);
      drupal_static_reset();
      drupal_language_initialize();
      drupal_page_header();
      drupal_path_initialize();
      menu_set_custom_theme();
      drupal_theme_initialize();
      module_invoke_all('init');

      ob_start();
      menu_execute_active_handler($_GET['q']);
      $body = ob_get_clean();
      $status = '200 OK';
      $headers = array();

      foreach (drupal_get_http_header() as $key => $value) {
        if ($key == 'status') {
          $status = $value;
        }
        else {
          $headers[] = $key;
          $headers[] = $value;
        }
      }

      return array($status, $headers, $body);
    }

}

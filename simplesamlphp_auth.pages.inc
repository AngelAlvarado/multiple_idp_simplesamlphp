<?php
/**
 * @file
 * Non administrative page callbacks for SimpleSamlPHP Auth module.
 * This module belongs to Andreas Åkre Solberg, Snorre Løvås and Steve Moitozo (Maintenance)
 * the adjustments we're doing is to allow multiple IDPs and SPs on the same website with custom
 * logic from TA
 * @version 7.x.3.5
 * @author Pablo Tapia <pablo.orozco@ingenia.com>
 * @author Angel Alvarado <angel.angelio.ingenia@gmail.com>
 */

/**
 * We load the custom Simple SAML Auth object to store all the IDP information
 */
module_load_include('inc', 'simplesamlphp_auth', 'includes/simplesamlphp_auth.drupal');

/**
 * Represents the Drupal page (saml_login), which triggers user authentication against
 * the SimpleSAMLphp service provider.
 * @see ssaml_auth_load
 */
function simplesamlphp_auth_loginpage($sp = NULL) {
  try {
    $simplesamlphp_drupal = SimpleSAML_Drupal::factory();
    $simplesamlphp_drupal->load($sp);
  }
  catch (Exception $e) {
    watchdog_exception('simplesamlphp_auth', $e);
  } // End try - catch.

  $idp_st = !empty($simplesamlphp_drupal->getAuthSourceAttributes()) ? $simplesamlphp_drupal->getAuthSourceAttributes()->id : $sp;

  global $user;
  global $base_url;

  module_load_include('inc', 'simplesamlphp_auth');
  // The user is not logged into Drupal.
  if ($user->uid == 0) {
    _simplesaml_auth_login_register();
  }
  else {
    // The user is already logged into Drupal.
    simplesaml_auth_moderate_local_login();
  }
  // End if - else.

  $output = NULL;

  // There was a problem, we can't go on, but we don't want to tell the user any specifics either.
  if ($simplesamlphp_drupal->doSanitizeChecking() === FALSE) {
    drupal_set_message(t("We're sorry. There was a problem attempting login. The issue has been logged for the administrator."), 'error');
    drupal_goto('user/login');
  }
  // End if.

  $return_to = NULL;

  /**
   * Support for deep linking.
   */
  // See if a URL has been explicitly provided in ReturnTo. If so, use it (as long as it points to this site).
  if ((isset($_REQUEST['ReturnTo']) && $_REQUEST['ReturnTo']) &&
    (valid_url($_REQUEST['ReturnTo']) && stristr($_REQUEST['ReturnTo'], $base_url))
  ) {
    $return_to = $_REQUEST['ReturnTo'];
    // If not, see if a REFERER URL is available. If so, use it (as long as it points to this site).
  }
  elseif ((isset($_SERVER['HTTP_REFERER']) && $_SERVER['HTTP_REFERER']) &&
    (valid_url($_SERVER['HTTP_REFERER']) && stristr($_SERVER['HTTP_REFERER'], $base_url))
  ) {
    $return_to = $_SERVER['HTTP_REFERER'];
  }
  // End if - elseif.

  // If the user is anonymous, set the cookie (if we can) and require authentication.
  if ($user->uid == 0) {
    if ($return_to) {
      // Set the cookie so we can deliver the user to the place they started.
      setrawcookie('simplesamlphp_auth_returnto', $return_to, time() + 60 * 60);
    }
    // End if.

    // Require the user to be authenticated.
    setcookie('tytaa', (string) $idp_st, time() + (60 * 60 * 24 * 30), '/');
    $simplesamlphp_drupal->getSimpleSAMLAuthSimple()->requireAuth();
  }
  else {
    // If the user is authenticated, send them along.
    $go_to_url = NULL;
    setcookie('_lta', (string) $idp_st, time() + (60 * 60 * 24 * 30), '/');
    // Check to see if we've set a cookie. If there is one, give it priority.
    if (isset($_COOKIE['simplesamlphp_auth_returnto']) && $_COOKIE['simplesamlphp_auth_returnto']) {
      // Use the cookie for the ReturnTo.
      $go_to_url = $_COOKIE['simplesamlphp_auth_returnto'];
      // Unset the cookie.
      setrawcookie('simplesamlphp_auth_returnto', '');
    }
    elseif ($return_to) {
      $go_to_url = $return_to;
    }
    // End if - elseif.

    // If a ReturnTo has been set.
    if ($go_to_url) {
      $parsed_gotourl = drupal_parse_url($go_to_url);
      drupal_goto($parsed_gotourl['path'], $parsed_gotourl);
    }
    else {
      drupal_goto('user/' . $user->uid);
    }
    // End if - else.
  }
  // End if - else.

  return $output;
}


/**
 * In order to know what IdP we are working with.
 *
 * Validates if the URL contains GET parameter.
 */
function _saml_redirect() {
  if (!isset($_GET['s'])) {
    return FALSE;
  }
  return TRUE;
}

/**
 * Create a page to redirect SSO users.
 *
 * Background: If the SSO process is done via GET
 * deeplinking links usually are way too long.
 *
 * Using the entry point saml_login/#idp works smoothly.
 * However, there are text editors (i.e. MSWord) that truncate URLs.
 * this usually happens when  URLs are more than 600 charactes long.
 * This is a problem because we lost vital data in the URL
 *
 * We create this new entrypoint
 * which works as a redirection which is used to point deeplinking
 * links to it saml_redirec?s=IdIdP&destination='RelayState'.
 * This way the URL lenghts are manage on Drupal side
 * and are not truncate by third party tools.
 *
 * @param Bool $page_callback_result
 *   Wheter or not we should redirect users.
 */
function _saml_redirection_delivery($page_callback_result) {

  if (isset($_GET['s']) && $page_callback_result) {
    drupal_add_http_header('Content-Type', 'text/html; UTF-8');
    drupal_add_http_header('Connection', 'keep-alive');
    drupal_add_http_header('Content-Language', 'en');
    $idp = $_GET['s'];
    $get_d = drupal_get_destination();
    if (isset($_GET['destination'])) {
      // Destination may have unencoded parameters.
      $tempd = request_uri();
      $dpos = stripos($tempd, '&destination=');
      // If URL contains destination parameter then remove it?
      if ($dpos !== FALSE) {
        $get_d['destination'] = substr($tempd, strpos($tempd, '=', $dpos) + 1);
      }
      // Trim & encode.
      // We must encode the destination parameter
      // This will be the Relaystate.
      $dest = ltrim($get_d['destination'], '/');
      $dest = drupal_encode_path($dest);
    }
    else {
      $dest = '';
    }
    $meta_saml = [
      '#type'       => 'html_tag',
      '#tag'        => 'meta',
      '#attributes' => [
        'content'    => "0; url=/saml_login/" . $idp . "?destination=" . $dest,
        'http-equiv' => 'refresh',
      ],
      '#weight'     => '-99999',
    ];
    drupal_add_html_head($meta_saml, 'meta_saml');
    $tags = ['center', 'span'];
    // @todo let's modify this message via the UI probably via a renderable array.
    print drupal_render_page(filter_xss('<center><span style="font-size:16.0pt;font-family:"Calibri",sans-serif">Redirecting now, please wait....</span></center>', $tags));
    drupal_page_footer();
  }
  else {
    // Print a 403 page.
    drupal_add_http_header('Status', '403 Forbidden');
    watchdog('access denied', check_plain($_GET['q']), NULL, WATCHDOG_WARNING);

    // Keep old path for reference, and to allow forms to redirect to it.
    if (!isset($_GET['destination'])) {
      $_GET['destination'] = $_GET['q'];
    }

    $path = drupal_get_normal_path(variable_get('site_403', ''));
    if ($path && $path != $_GET['q']) {
      // Custom 403 handler. Set the active item in case there are tabs to
      // display or other dependencies on the path.
      menu_set_active_item($path);
      $return = menu_execute_active_handler($path, FALSE);
    }

    if (empty($return) || $return == MENU_NOT_FOUND || $return == MENU_ACCESS_DENIED) {
      // Standard 403 handler.
      drupal_set_title(t('Access denied'));
      $return = t('You are not authorized to access this page.');
    }
    print drupal_render_page($return);
  }
}

<?php

/**
 * @file
 * Admin include file for admin settings form.
 * This file includes all the forms / hooks needed to build the admin settings pages for the SAML and
 * the IDPs
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
 * Implements settings for SAML Auth management page.
 * Generates the page that allows users to configure the standard configuration for the SAML Basic settings
 * The difference between this and the IDP settings is that we storage this in drupal global variables so
 * they are available throught the whole site .. this is the default behavior from the module
 */
function simplesamlphp_auth_settings() {
  global $base_url;
  try {
    $simplesamlphp_auth_saml_version = SimpleSAML_Drupal::factory()->getSimpleSAMLVersion();
  }
  catch (Exception $e) {
    watchdog_exception('simplesamlphp_auth', $e);
    drupal_set_message(t($e->getMessage()), 'error');
  } // end try - catch
  if (!empty($simplesamlphp_auth_saml_version)) {
    $ver = explode('.', $simplesamlphp_auth_saml_version);
    if (!($ver[0] >= 1 && $ver[1] >= 5)) {
      drupal_set_message(t( "Please upgrade SimpleSAMLphp. You are using %ssp_version", array('%ssp_version' => $simplesamlphp_auth_saml_version)), 'warning');
    } // end if
  } // end if

  $roles = user_roles( TRUE );

  $form['simplesamlphp_auth_grp_setup'] = array(
    '#type' => 'fieldset',
    '#title' => t( 'Basic Setup' ),
    '#collapsible' => FALSE,
  );
  $form['simplesamlphp_auth_grp_setup']['simplesamlphp_auth_activate'] = array(
    '#type' => 'checkbox',
    '#title' => t('Activate authentication via SimpleSAMLphp'),
    '#default_value' => variable_get('simplesamlphp_auth_activate', FALSE),
    '#description' => t( 'Checking this box before configuring the module could lock you out of Drupal.' ),
  );
  $form['simplesamlphp_auth_grp_setup']['simplesamlphp_auth_installdir'] = array(
    '#type' => 'textfield',
    '#title' => t( 'Installation directory (default: /var/simplesamlphp)' ),
    '#default_value' => variable_get('simplesamlphp_auth_installdir', '/var/simplesamlphp'),
    '#description' => t('The base directory of simpleSAMLphp. Absolute path with no trailing slash.'),
  );
  $form['simplesamlphp_auth_grp_setup']['simplesamlphp_auth_forcehttps'] = array(
    '#type' => 'checkbox',
    '#title' => t('Force https for login links'),
    '#default_value' => variable_get('simplesamlphp_auth_forcehttps', TRUE),
    '#description' => t('Should be enabled on production sites.'),
  );

  $form['simplesamlphp_auth_grp_reg'] = array(
    '#type' => 'fieldset',
    '#title' => t('User Provisioning'),
    '#collapsible' => TRUE,
    '#collapsed' => FALSE,
  );
  $form['simplesamlphp_auth_grp_reg']['simplesamlphp_auth_registerusers'] = array(
    '#type' => 'checkbox',
    '#title' => t('Register users (i.e., auto-provisioning)'),
    '#default_value' => variable_get('simplesamlphp_auth_registerusers', TRUE),
    '#description' => t("Determines wether or not the module should automatically create/register new Drupal accounts for users that authenticate using SimpleSAMLphp. Unless you've done some custom work to provision Drupal accounts with the necessary authmap entries you will want this checked. NOTE: If unchecked each user must already have been provisioned a Drupal account with an appropriate entry in the authmap table before logging in. Otherwise they will receive a notice and be denied access. Be aware that simply creating a Drupal account will not create the necessary entry in the authmap table."),
  );
  $form['simplesamlphp_auth_grp_auth'] = array(
    '#type' => 'fieldset',
    '#title' => t('Drupal Authentication'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
  );
  $form['simplesamlphp_auth_grp_auth']['simplesamlphp_auth_allowsetdrupalpwd'] = array(
    '#type' => 'checkbox',
    '#title' => t('Allow SAML users to set Drupal passwords.'),
    '#default_value' => variable_get('simplesamlphp_auth_allowsetdrupalpwd', FALSE),
    '#description' => t('Check this box if you want to let people set passwords for their local Drupal accounts. This will allow users to log in using either SAML or a local Drupal account. Disabling this removes the password change fields from the user profile form.<br/>NOTE: In order for them to login using their local Drupal password you must allow local logins with the settings below.'),
  );
  $form['simplesamlphp_auth_grp_auth']['simplesamlphp_auth_allowdefaultlogin'] = array(
    '#type' => 'checkbox',
    '#title' => t('Allow authentication with local Drupal accounts'),
    '#default_value' => variable_get('simplesamlphp_auth_allowdefaultlogin', TRUE),
    '#description' => t('Check this box if you want to let people log in with local Drupal accounts (without using simpleSAMLphp). If you want to restrict this privilege to certain users you can enter the Drupal user IDs in the field below.'),
  );
  $form['simplesamlphp_auth_grp_auth']['simplesamlphp_auth_allowdefaultloginroles'] = array(
    '#type' => 'select',
    '#size' => 3,
    '#options' => $roles,
    '#multiple' => TRUE,
    '#title' => t('Which ROLES should be allowed to login with local accounts?'),
    '#default_value' => variable_get('simplesamlphp_auth_allowdefaultloginroles', array()),
    '#description' => t('Roles that should be allowed to login without simpleSAMLphp. Examples are dev/admin roles or guest roles.'),
  );
  $form['simplesamlphp_auth_grp_auth']['simplesamlphp_auth_allowdefaultloginusers'] = array(
    '#type' => 'textfield',
    '#title' => t('Which users should be allowed to login with local accounts?'),
    '#default_value' => variable_get('simplesamlphp_auth_allowdefaultloginusers', ''),
    '#description' => t('Example: <i>1,2,3</i><br />A comma-separated list of user IDs that should be allowed to login without simpleSAMLphp. If left blank, all local accounts can login.'),
  );
  $form['simplesamlphp_auth_grp_auth']['simplesamlphp_auth_logoutgotourl'] = array(
    '#type' => 'textfield',
    '#title' => t( 'Optionally, specify a URL for users to go to after logging out' ),
    '#default_value' => variable_get('simplesamlphp_auth_logoutgotourl', ''),
    '#description' => t('Example: @base_url', array('@base_url' => $base_url)),
  );
  /**
   * Since the module will now take values from multiples IDPs we don't need to specify a
   * source, the logic will be if the admin creates a new IDP then it's going to be available
   * nevertheless the default value for the IDP is default-sp
   */
  return system_settings_form($form);
}
/**
 * Implements settings for the IDPs management page.
 * Generates the page for the user to manage the differents IDPs .. it's very IMPORTANT to highlight
 * the fact that these forms will allow the settings for the IDPs inside Drupal so the modify version
 * of the login form knows what domains to look and the configurations for each one when mapping users
 * from the SAML to the Drupal but these configurations ( i.e. IDPs ) must also be replied in the configuration
 * file from the simplesamlphp under metadata and in the authsources file so the library knows there are new
 * IDPs
 */
function simplesamlphp_auth_idp_settings() {
  global $base_url;
  try {
    $simplesamlphp_auth_saml_version = SimpleSAML_Drupal::factory()->getSimpleSAMLVersion();
  }
  catch (Exception $e) {
    watchdog_exception('simplesamlphp_auth', $e);
    drupal_set_message(t($e->getMessage()), 'error');
  } // end try - catch
  if (!empty($simplesamlphp_auth_saml_version)) {
    $ver = explode('.', $simplesamlphp_auth_saml_version);
    if (!($ver[0] >= 1 && $ver[1] >= 5)) {
      drupal_set_message(t("Please upgrade SimpleSAMLphp. You are using %ssp_version", array('%ssp_version' => $simplesamlphp_auth_saml_version)), 'warning');
    } // end if
  } // end if

  $output = array(
    'introduction' => array(
      '#markup' => '<p>The following table contains the active IDP domains on the system.</p>'
    ),
    'table'   => array(
      '#theme'  => 'table',
      '#header' => array(
          t('Company'),
          t('IDP Domain'),
          array('data' => t('Actions'), 'colspan' => 2),
      ),
      '#rows' => _simplesamlphp_auth_idp_rows(),
      '#attributes' => array('id' => 'domains')
    ),
    'form' => drupal_get_form('simplesamlphp_auth_form')
  );
  return $output;
}
/**
 * This method returns an array with all the data from the IDPs created on the system
 * @see simplesamlphp_auth_idp_settings
 */
function _simplesamlphp_auth_idp_rows() {
  $rows = array();
  $resultSet = db_query("SELECT id, company, domain FROM {saml_idp_settings} WHERE active = 1")->fetchAll();
  if (!empty($resultSet)) {
    foreach ($resultSet as $record) {
      $rows[] = array(
        t('%company', array('%company' => $record->company)),
        t('%domain', array('%domain' => $record->domain)),
        l(t('Edit'), "admin/config/people/simplesamlphp_auth/{$record->id}/edit"),
        l(t('Delete'), "admin/config/people/simplesamlphp_auth/{$record->id}/delete"),
      );
    } // end foreach
    return $rows;
  } // end if
  return array(
    array('data' => array(
        array('data' => t('No active IDPs on the current system'), 'colspan' => 4)
      )
    )
  );
}
/**
 * Implements hook_form()
 * Creates the form that allows the add / edit for IDPs
 * @see ssaml_auth_load
 */
function simplesamlphp_auth_form($form, &$form_state, $idp = NULL) {
  $form['simplesamlphp_auth_grp_user'] = array(
    '#type' => 'fieldset',
    '#title' => (NULL !== $idp && !empty($idp->id)) ? t('Edit IDP Settings') : t('Register new IDP Domain'),
    '#collapsible' => TRUE,
    '#collapsed' => (NULL !== $idp && !empty($idp->id)) ? FALSE : TRUE
  );
  $form['simplesamlphp_auth_grp_user']['simplesamlphp_auth_source'] = array(
    '#type' => 'textfield',
    '#title' => t("What name do you want to give to this connection"),
    '#default_value' => isset($idp->source_name) && !empty($idp->source_name) ? $idp->source_name : '',
    '#description' => t(
      '<i>IMPORTANT:</i> Register this IDP source on the config/authsources.php file
      located on the installation dir '. variable_get('simplesamlphp_auth_installdir') .' the name of the
      Auth Source must be the same as the one registered on this field.' ),
    '#required' => TRUE,
  );
  $form['simplesamlphp_auth_grp_user']['simplesamlphp_auth_company_name'] = array(
    '#type' => 'textfield',
    '#title' => t("What's the company name for the new IDP"),
    '#default_value' => isset($idp->company) && !empty($idp->company) ? $idp->company : '',
    '#description' => t('Example: <i>Tax Analysts</i>'),
    '#required' => TRUE,
  );
  $form['simplesamlphp_auth_grp_user']['simplesamlphp_auth_domain'] = array(
    '#type' => 'textfield',
    '#title' => t("Which IDP domain you want to register"),
    '#default_value' => isset($idp->domain) && !empty($idp->domain) ? $idp->domain : '',
    '#description' => t('Example: <i>tax.org</i>'),
    '#required' => TRUE,
  );
  if (NULL !== $idp && !empty($idp->attributes)) {
    $attributes = unserialize($idp->attributes);
  } // end if

  $form['simplesamlphp_auth_grp_user']['simplesamlphp_auth_user_name'] = array(
    '#type' => 'textfield',
    '#title' => t("Which attribute from the IDP should be used as user's alias"),
    '#default_value' => isset($attributes['username']) && !empty($attributes['username']) ? $attributes['username'] : '',
    '#description' => t('Example: <i>eduPersonPrincipalName</i> or <i>displayName</i><br />If the attribute is multivalued, the first value will be used.'),
    '#required' => TRUE,
  );
  $form['simplesamlphp_auth_grp_user']['simplesamlphp_auth_unique_id'] = array(
    '#type' => 'textfield',
    '#title' => t('Which attribute from the IDP should be used as unique identifier for the user'),
    '#default_value' => isset($attributes['unique_id']) && !empty($attributes['unique_id']) ? $attributes['unique_id'] : '',
    '#description' => t('Example: <i>eduPersonPrincipalName</i> or <i>eduPersonTargetedID</i><br />If the attribute is multivalued, the first value will be used. (If left empty the email address will be used)'),
    '#required' => TRUE,
  );
  $form['simplesamlphp_auth_grp_user']['simplesamlphp_auth_mailattr'] = array(
    '#type' => 'textfield',
    '#title' => t('Which attribute from simpleSAMLphp should be used as user mail address'),
    '#default_value' => isset($attributes['mailattr']) && !empty($attributes['mailattr']) ? $attributes['mailattr'] : '',
    '#description' => t('Example: <i>mail</i><br />If the user attribute is multivalued, the first value will be used.'),
    '#required' => TRUE,
  );
  $form['simplesamlphp_auth_grp_user']['simplesamlphp_auth_csfields'] = array(
    '#type' => 'textarea',
    '#title' => t('Additional attributes'),
    '#default_value' => isset($attributes['cs_fields']) && !empty($attributes['cs_fields']) ? implode('|', $attributes['ns_fields']) : '',
    '#description' => t('A pipe separated list of attributes that would map to custom fields.<br />Example: <i>CustomField:SAMLattr|CustomField:SAMLattr...</i> <br />For instance: <i>firstname:userName|companyname:company</i>'),
  );
  $form['actions'] = array('#type' => 'actions');
  $form['simplesamlphp_auth_grp_user']['actions']['submit'] = array(
    '#type' => 'submit',
    "#value" => (NULL !== $idp && !empty($idp->id)) ? t('Save') : t('Create'),
    "#submit" => array('simplesamlphp_auth_form_submit'),
  );
  if (isset($idp->id) && !empty($idp->id)) {
      $form['simplesamlphp_auth_grp_user']['actions']['cancel'] = array(
        '#type' => 'submit',
        '#value' => 'Cancel',
        '#limit_validation_errors' => array(),
        '#submit' => array('simplesamlphp_auth_form_cancel')
      );
      $form['simplesamlphp_auth_grp_user']['simplesamlphp_auth_idp_id'] = array(
        '#type' => 'hidden',
        '#value' => $idp->id,
      );
  } // end if
  $form['#validate'][] = 'simplesamlphp_auth_form_validate';
  /**
   * For this specific implementation the role assignation will come from NS based on the only
   * attribute that's mandatory which is the contract id so we don't need this options
   */
  return $form;
}
/**
 * Implements hook_submit()
 */
function simplesamlphp_auth_form_submit($form, &$form_state) {
  $data = array(
    'source_name' => $form_state['values']['simplesamlphp_auth_source'],
    'company' => $form_state['values']['simplesamlphp_auth_company_name'],
    'domain' => $form_state['values']['simplesamlphp_auth_domain'],
    'active' => 1
  );
  $attributes = array(
    'username' => $form_state['values']['simplesamlphp_auth_user_name'],
    'unique_id' => $form_state['values']['simplesamlphp_auth_unique_id'],
    'mailattr' => $form_state['values']['simplesamlphp_auth_mailattr'],
  );
  /**
   * Custome attributes are not mandatory
   */
  if (!empty( $form_state['values']['simplesamlphp_auth_csfields'])) {
    $attributes['cs_fields'] = explode('|', $form_state['values']['simplesamlphp_auth_csfields']);
  } // end if
  $data['attributes'] = serialize($attributes);
  try {
    if (isset( $form_state['values']['simplesamlphp_auth_idp_id'] ) && (int) $form_state['values']['simplesamlphp_auth_idp_id'] > 0) {
      $query_update = db_update('saml_idp_settings');
      $query_update->fields($data);
      $query_update->condition('id', $form_state['values']['simplesamlphp_auth_idp_id']);
      $query_update->execute();
      drupal_set_message(t('IDP settings updated for %company' , array('%company' => $data['company'])), 'status');
      $form_state['redirect'] = 'admin/config/people/simplesamlphp_auth/idp';
      return;
    } // end if
    $query_insert = db_insert('saml_idp_settings');
    $query_insert->fields($data);
    $query_insert->execute();
    drupal_set_message(t('New IDP added successfully, don\'t forget to also add the new IDP to the authsources file for simplesamlphp'), 'status');
  }
  catch(Exception $e) {
    drupal_set_message(t('Something went wrong, message details: %message', array('%message' => $e->getMessage())), 'error');
  } // end try -catch
}
/**
 * Implements the cancel action on the edit form when the button is pressed
 */
function simplesamlphp_auth_form_cancel() {
  // We redirect the user when he / she pressed the Cancel Button
  drupal_goto('admin/config/people/simplesamlphp_auth/idp');
}
/**
 * Implements hook_validate()
 * Custom validation for the IDP form, we're just checking the company or the IDP are not already
 * registered on the system
 */
function simplesamlphp_auth_form_validate($form, &$form_state) {
  if ($form_state['values']['op'] != t('Save')) {
    $check_source = db_query("SELECT id FROM {saml_idp_settings} WHERE source_name = :s",
      array(':s' => $form_state['values']['simplesamlphp_auth_source']))->fetchAll();
    $check_company = db_query( "SELECT id FROM {saml_idp_settings} WHERE company = :n",
      array(':n' => $form_state['values']['simplesamlphp_auth_company_name']))->fetchAll();
    $check_domain =  db_query( "SELECT id FROM {saml_idp_settings} WHERE domain = :d",
      array(':d' => $form_state['values']['simplesamlphp_auth_domain']))->fetchAll();

    if (!empty( $check_source)) {
      form_set_error('simplesamlphp_auth_source', t('This source name has already been registered, try a different one.'));
    } // end if
    if(!empty($check_company)) {
      form_set_error('simplesamlphp_auth_company_name', t('A company with that name already exists, try another one.'));
    } // end if
    if(!empty($check_domain)) {
      form_set_error('simplesamlphp_auth_domain', t('This domain name is already active on the system, please try a different one.'));
    } // end if
  } // end if
}
/**
 * Confirmation form for the deletion of an IDP.  Deletion takes place
 * in simplesamlphp_auth_delete_submit().
 * @see ssaml_auth_load
 */
function simplesamlphp_auth_delete($form, &$form_state, $idp) {
  $form['idp'] = array('#type' => 'hidden', '#value' => $idp->id);
  return confirm_form($form, t('Are you sure you want to delete the IDP for %name ?', array('%name' => $idp->company)),
    'admin/config/people/simplesamlphp_auth/idp', t('This action cannot be undone.'), t('Delete'), t('Cancel'));
}
/**
 * Submit hook for the delete of the IDP.
 */
function simplesamlphp_auth_delete_submit($form, &$form_state) {
  $id = $form_state['values']['idp'];
  try {
    db_delete('saml_idp_settings')->condition('id', $id)->execute();
    drupal_set_message(t('IDP deleted succesfully' ), 'status');
    $form_state['redirect'] = 'admin/config/people/simplesamlphp_auth/idp';
  }
  catch(Exception $e) {
    drupal_set_message(t('Something went wrong, message details: %message', array('%message' => $e->getMessage())), 'error');
  } // end try - catch
}

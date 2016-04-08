/**
 * On restricted modal window (if the user is anonymous)
 * check if they have the idp cookie to iniciate the sso process
 * @check module that generates the modal window
 * @todo change the name of this file to 'autoredirec'
 * @todo in the UI add a list of URLs where this will be added
 */
var sso = getCookie("_lta");
if (sso != "") {
  window.location = 'http://' + window.location.hostname + '/saml_redirect?s=' + sso + '&destination=' + window.location.pathname;
}

function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for(var i=0; i<ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1);
        if (c.indexOf(name) == 0) return c.substring(name.length,c.length);
    }
    return "";
}

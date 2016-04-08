/**
 * Verifies if users have a cookie to trigger the sso login redirect; only for anonymous users
 * If cookie exist and users click on specific DOM elements then take them to SSO
 * @todo the CSS IDs are hardcoded here should be added to the UI
 */
document.addEventListener("DOMContentLoaded", function(e){
  /*
  Gets login button DOM, on clic checks cookie and redirects if necesary
   */
  var elemm = document.getElementById('login_s') || document.getElementById('login-link-s');
  try {
    elemm.onclick = function(e) {
        var sso=getCookieLogin("_lta");
        if (sso!="") {
            url_s = window.location.href;
            if( /[?&]esq%3D/.test(location.href) || /[?&]esq=/.test(location.href) ){
                var queryString = url_s.substring(url_s.lastIndexOf("?") + 1);
                var rl = 'http://' + window.location.hostname + '/saml_redirect?s='
                    + sso + '&destination=' + window.location.pathname + '?'
                    + queryString;
            }else{
                var rl = 'http://' + window.location.hostname + '/saml_redirect?s='
                    + sso + '&destination=' + window.location.pathname ;
            }
            window.location = rl;
            var evt = e ? e:window.event;
            if (evt.preventDefault) evt.preventDefault();
            evt.returnValue = false;
            return false;
        }
    }

    function getCookieLogin(cname) {
        var name = cname + "=";
        var ca = document.cookie.split(';');
        for(var i=0; i<ca.length; i++) {
            var c = ca[i];
            while (c.charAt(0)==' ') c = c.substring(1);
            if (c.indexOf(name) == 0) return c.substring(name.length,c.length);
        }
        return "";
    }
  } catch(err) {
    console.log("not able to set SAML redirect" + err);
  }
});



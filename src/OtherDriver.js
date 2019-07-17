// local storage keys
import LSKEYS from './LSKEYS'

/**
 * Other AuthDriver
 * implements AuthDriver interface
 * @param opts options object requires:
 *  - TENANT OAuth provider url
 *  - CLIENT_ID client application id
 *  - REDIRECT_URI uri to redirect to after a login/logout request
 * @constructor
 */
function OtherDriver(opts) {
	this.id_token = null;
	this.authContext = null;
	// required options
	if (!opts.TENANT) {
		throw new Error('TENANT is required in OtherDriver');
	}
	this.TENANT = opts.TENANT;
	if (!opts.CLIENT_ID) {
		throw new Error('CLIENT_ID is required in OtherDriver');
	}
	this.CLIENT_ID = opts.CLIENT_ID;
	if (!opts.REDIRECT_URI) {
		throw new Error('REDIRECT_URI is required in OtherDriver');
	}
	this.REDIRECT_URI = opts.REDIRECT_URI;
	if (!opts.OAUTHVERSION) {
		throw new Error('OAUTHVERSION is required in OtherDriver');
	}
	this.OAUTHVERSION = opts.OAUTHVERSION;
	if (!opts.TOKENTYPE) {
		throw new Error('TOKENTYPE is required in OtherDriver');
	} else if (!(opts.TOKENTYPE === 'token' || opts.TOKENTYPE === 'id_token')) {
		throw new Error('Invalid TOKENTYPE')
	}
	this.TOKENTYPE = opts.TOKENTYPE;
	this.SCOPE = opts.SCOPE;
	Object.defineProperties(this, {
		idToken: {
			get: () => this.id_token,
			set: token => {
				// logged in
				window.localStorage.setItem(LSKEYS.ID_TOKEN, token);
				this.id_token = token;
				// if reactiveChange is defined in authContext then update the reactive interface
				if (this.authContext.reactiveChange) {
					this.authContext.reactiveChange('idToken', token);
					this.authContext.reactiveChange('decodedToken', this.decodedToken)
				}
			}
		},
    decodedToken: {
      get: () => {
				if (this.idToken.includes('.')) {
					let splitToken = this.idToken.split('.')
					return {
						header: decode(splitToken[0]),
						payload: decode(splitToken[1])
					}
				} else {
					return this.idToken;
				}
      }
    },
		state: {
			get: () => window.localStorage.getItem(LSKEYS.STATE),
			set: state => window.localStorage.setItem(LSKEYS.STATE, state)
		}
	});
}

/**
 * handles returning redirect by decoding the hash that OAuth provider returns
 * also handles loading id_token stored in localStorage
 * then initializes http instance
 * @param authContext Authentication handler object
 */
OtherDriver.prototype.init = function(authContext) {
	// set the authContext
	this.authContext = authContext;
	// is the application coming from a redirect?
	let returned = readHash(window.location.hash);
	if (returned) {
		// hash contains the access token
		if (returned.access_token) {
			if(returned.state) {
				//  Check state
				if (returned.state !== this.state) {
					throw new Error('Token state does not match stored state');
				}
			}
			this.idToken = returned.access_token;
		}
	} else {
		// not coming from redirect, so check if id token is stored in localStorage
		let idToken = window.localStorage.getItem(LSKEYS.ID_TOKEN);
		if (idToken) {
			// id token was stored, so we are logged in
			this.idToken = idToken;
		}
	}
};

/**
 * Checks the state on an id_token with the saved state,
 * then saves id_token on success
 * @param token
 */
OtherDriver.prototype.login = function(silent) {
	// redirect to login
	window.location.replace(this.makeLoginUri(silent));
};
/**
 * Clear localStorage and redirect to microsoft logout endpoint
 */
OtherDriver.prototype.logout = function () {
  window.localStorage.removeItem(LSKEYS.ID_TOKEN)
  window.localStorage.removeItem(LSKEYS.STATE)
  window.localStorage.removeItem(LSKEYS.AUTH_STYLE)
  window.location.replace(`${this.TENANT}/${this.OAUTHVERSION}/logout?post_logout_redirect_uri=${this.REDIRECT_URI}`)
}

/**
 * generates and saves a state to be compared on successful redirect, then returns a uri to login to provider
 * @param silent whether to add a no prompt option to the uri
 * @return {string} uri to request id token from provider
 */
OtherDriver.prototype.makeLoginUri = function (silent) {
	// generate and save a state to localStorage
	let state = generateNonce();
	this.state = state;
	// generate the base uri
	let uri = `${this.TENANT}/${this.OAUTHVERSION}/authorize?client_id=${this.CLIENT_ID}&response_type=${this.TOKENTYPE}&redirect_uri=${this.REDIRECT_URI}${(this.SCOPE ? '&scope=' + this.SCOPE : '')}&state=${state}`
	// if silent then uri will not prompt, but will error if not logged in
	if (silent) {
		uri += '&prompt=none'
	}
	return uri;
};

/**
 * Clear localStorage and redirect to logout endpoint
 * **TODO** logout link doesn't work
 */
OtherDriver.prototype.logout = function() {
	window.localStorage.removeItem(LSKEYS.ID_TOKEN);
	window.localStorage.removeItem(LSKEYS.STATE);
	window.localStorage.removeItem(LSKEYS.AUTH_STYLE);
	window.location.replace(`${this.TENANT}/${this.OAUTHVERSION}/logout?post_logout_redirect_uri=${this.REDIRECT_URI}`);
};

/**
 * uses an iframe to send a silent login request to provider for a new id_token
 * @return {Promise}
 */
OtherDriver.prototype.backgroundLogin = async function () {
  // create iframe
  const frame = document.createElement('iframe')
  frame.setAttribute('id', 'auth-frame')
  frame.setAttribute('aria-hidden', 'true')
  frame.style.visibility = 'hidden'
  frame.style.position = 'absolute'
  frame.style.width = frame.style.height = frame.borderWidth = '0px'
  const attachedFrame = document.getElementsByTagName('body')[0].appendChild(frame)
  let resetEvent = await runIframeNavigation(attachedFrame, 'about:blank')
  let authEvent = await runIframeNavigation(resetEvent.target, this.makeLoginUri(true))
  // process the response from the url hash
  let response = readHash(authEvent.target.contentWindow.location.hash)
  if (!response || response.error_description) {
    // if there's an issue when renewing the token, force a full login
    this.login()
  }
  if (response.id_token) {
    this.idToken = response.id_token
  }
  // remove iframe
  attachedFrame.remove()
  return response.id_token
}

function runIframeNavigation (iframe, url) {
  return new Promise(resolve => {
    iframe.onload = loadEvent => resolve(loadEvent)
    iframe.setAttribute('src', url)
  })
}

/**
 * Decodes a url safe base64 string to object
 * @param b64
 * @return {any}
 */
function decode (b64) {
  try {
    return JSON.parse(window.atob(b64.replace(/-/g, '+').replace(/_/g, '/')))
  } catch (e) {
    if (e.name === 'SyntaxError') {
      return { error: 'Malformed token' }
    } else {
      throw e
    }
  }
}
// str byteToHex(uint8 byte)
//   converts a single byte to a hex string
function byteToHex (byte) {
  return ('0' + byte.toString(16)).slice(-2)
}

/**
 * Converts a hash response to an object
 * @param hash
 * @return hash object or false
 */
function readHash(hash) {
	let hsh = hash.slice(1);
	if (hsh) {
		let list = hsh.split('&');
		let obj = {};
		for (let kv of list) {
			let [key, val] = kv.split('=');
			obj[key] = decodeURIComponent(val);
		}
		return obj;
	}
	return false;
}

function generateNonce() {
	let arr = new Uint8Array(20);
	window.crypto.getRandomValues(arr);
	return [].map.call(arr, byteToHex).join('');
}

export {OtherDriver, OtherDriver as default};

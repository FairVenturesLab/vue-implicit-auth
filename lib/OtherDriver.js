'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});
exports.default = exports.OtherDriver = undefined;

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _LSKEYS = require('./LSKEYS');

var _LSKEYS2 = _interopRequireDefault(_LSKEYS);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; } // local storage keys


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
	var _this = this;

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
		throw new Error('Invalid TOKENTYPE');
	}
	this.TOKENTYPE = opts.TOKENTYPE;
	this.SCOPE = opts.SCOPE;
	Object.defineProperties(this, {
		idToken: {
			get: function get() {
				return _this.id_token;
			},
			set: function set(token) {
				// logged in
				window.localStorage.setItem(_LSKEYS2.default.ID_TOKEN, token);
				_this.id_token = token;
				// if reactiveChange is defined in authContext then update the reactive interface
				if (_this.authContext.reactiveChange) {
					_this.authContext.reactiveChange('idToken', token);
					_this.authContext.reactiveChange('decodedToken', _this.decodedToken);
				}
			}
		},
		decodedToken: {
			get: function get() {
				if (_this.idToken.includes('.')) {
					var splitToken = _this.idToken.split('.');
					return {
						header: decode(splitToken[0]),
						payload: decode(splitToken[1])
					};
				} else {
					return _this.idToken;
				}
			}
		},
		state: {
			get: function get() {
				return window.localStorage.getItem(_LSKEYS2.default.STATE);
			},
			set: function set(state) {
				return window.localStorage.setItem(_LSKEYS2.default.STATE, state);
			}
		}
	});
}

/**
 * handles returning redirect by decoding the hash that OAuth provider returns
 * also handles loading id_token stored in localStorage
 * then initializes http instance
 * @param authContext Authentication handler object
 */
OtherDriver.prototype.init = function (authContext) {
	// set the authContext
	this.authContext = authContext;
	// is the application coming from a redirect?
	var returned = readHash(window.location.hash);
	if (returned) {
		// hash contains the access token
		if (returned.access_token) {
			if (returned.state) {
				//  Check state
				if (returned.state !== this.state) {
					throw new Error('Token state does not match stored state');
				}
			}
			this.idToken = returned.access_token;
		}
	} else {
		// not coming from redirect, so check if id token is stored in localStorage
		var idToken = window.localStorage.getItem(_LSKEYS2.default.ID_TOKEN);
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
OtherDriver.prototype.login = function (silent) {
	// redirect to login
	window.location.replace(this.makeLoginUri(silent));
};
/**
 * Clear localStorage and redirect to microsoft logout endpoint
 */
OtherDriver.prototype.logout = function () {
	window.localStorage.removeItem(_LSKEYS2.default.ID_TOKEN);
	window.localStorage.removeItem(_LSKEYS2.default.STATE);
	window.localStorage.removeItem(_LSKEYS2.default.AUTH_STYLE);
	window.location.replace(this.TENANT + '/' + this.OAUTHVERSION + '/logout?post_logout_redirect_uri=' + this.REDIRECT_URI);
};

/**
 * generates and saves a state to be compared on successful redirect, then returns a uri to login to provider
 * @param silent whether to add a no prompt option to the uri
 * @return {string} uri to request id token from provider
 */
OtherDriver.prototype.makeLoginUri = function (silent) {
	// generate and save a state to localStorage
	var state = generateNonce();
	this.state = state;
	console.log(state);
	// generate the base uri
	var uri = this.TENANT + '/' + this.OAUTHVERSION + '/authorize?client_id=' + this.CLIENT_ID + '&response_type=' + this.TOKENTYPE + '&redirect_uri=' + this.REDIRECT_URI + (this.SCOPE ? '&scope=' + this.SCOPE : '') + '&state=' + state;
	// if silent then uri will not prompt, but will error if not logged in
	if (silent) {
		uri += '&prompt=none';
	}
	return uri;
};

/**
 * Clear localStorage and redirect to logout endpoint
 * **TODO** logout link doesn't work
 */
OtherDriver.prototype.logout = function () {
	window.localStorage.removeItem(_LSKEYS2.default.ID_TOKEN);
	window.localStorage.removeItem(_LSKEYS2.default.STATE);
	window.localStorage.removeItem(_LSKEYS2.default.AUTH_STYLE);
	window.location.replace(this.TENANT + '/' + this.OAUTHVERSION + '/logout?post_logout_redirect_uri=' + this.REDIRECT_URI);
};

/**
 * uses an iframe to send a silent login request to provider for a new id_token
 * @return {Promise}
 */
OtherDriver.prototype.backgroundLogin = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee() {
	var frame, attachedFrame, resetEvent, authEvent, response;
	return regeneratorRuntime.wrap(function _callee$(_context) {
		while (1) {
			switch (_context.prev = _context.next) {
				case 0:
					// create iframe
					frame = document.createElement('iframe');

					frame.setAttribute('id', 'auth-frame');
					frame.setAttribute('aria-hidden', 'true');
					frame.style.visibility = 'hidden';
					frame.style.position = 'absolute';
					frame.style.width = frame.style.height = frame.borderWidth = '0px';
					attachedFrame = document.getElementsByTagName('body')[0].appendChild(frame);
					_context.next = 9;
					return runIframeNavigation(attachedFrame, 'about:blank');

				case 9:
					resetEvent = _context.sent;
					_context.next = 12;
					return runIframeNavigation(resetEvent.target, this.makeLoginUri(true));

				case 12:
					authEvent = _context.sent;

					// process the response from the url hash
					response = readHash(authEvent.target.contentWindow.location.hash);

					if (!response || response.error_description) {
						// if there's an issue when renewing the token, force a full login
						this.login();
					}
					if (response.id_token) {
						this.idToken = response.id_token;
					}
					// remove iframe
					attachedFrame.remove();
					return _context.abrupt('return', response.id_token);

				case 18:
				case 'end':
					return _context.stop();
			}
		}
	}, _callee, this);
}));

function runIframeNavigation(iframe, url) {
	return new Promise(function (resolve) {
		iframe.onload = function (loadEvent) {
			return resolve(loadEvent);
		};
		iframe.setAttribute('src', url);
	});
}

/**
 * Decodes a url safe base64 string to object
 * @param b64
 * @return {any}
 */
function decode(b64) {
	try {
		return JSON.parse(window.atob(b64.replace(/-/g, '+').replace(/_/g, '/')));
	} catch (e) {
		if (e.name === 'SyntaxError') {
			return { error: 'Malformed token' };
		} else {
			throw e;
		}
	}
}
// str byteToHex(uint8 byte)
//   converts a single byte to a hex string
function byteToHex(byte) {
	return ('0' + byte.toString(16)).slice(-2);
}

/**
 * Converts a hash response to an object
 * @param hash
 * @return hash object or false
 */
function readHash(hash) {
	var hsh = hash.slice(1);
	if (hsh) {
		var list = hsh.split('&');
		var obj = {};
		var _iteratorNormalCompletion = true;
		var _didIteratorError = false;
		var _iteratorError = undefined;

		try {
			for (var _iterator = list[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
				var kv = _step.value;

				var _kv$split = kv.split('='),
				    _kv$split2 = _slicedToArray(_kv$split, 2),
				    key = _kv$split2[0],
				    val = _kv$split2[1];

				obj[key] = decodeURIComponent(val);
			}
		} catch (err) {
			_didIteratorError = true;
			_iteratorError = err;
		} finally {
			try {
				if (!_iteratorNormalCompletion && _iterator.return) {
					_iterator.return();
				}
			} finally {
				if (_didIteratorError) {
					throw _iteratorError;
				}
			}
		}

		return obj;
	}
	return false;
}

function generateNonce() {
	var arr = new Uint8Array(20);
	window.crypto.getRandomValues(arr);
	return [].map.call(arr, byteToHex).join('');
}

exports.OtherDriver = OtherDriver;
exports.default = OtherDriver;
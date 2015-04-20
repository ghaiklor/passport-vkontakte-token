var util = require('util');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;

util.inherits(VKontakteTokenStrategy, OAuth2Strategy);

/**
 * `Strategy` constructor.
 * The Vkontakte authentication strategy authenticates requests by delegating to Vkontakte using OAuth2 access tokens.
 * Applications must supply a `verify` callback which accepts a accessToken, refreshToken, profile and callback.
 * Callback supplying a `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurs, `error` should be set.
 *
 * Options:
 * - clientID          Identifies client to Vkontakte App
 * - clientSecret      Secret used to establish ownership of the consumer key
 * - passReqToCallback If need, pass req to verify callback
 *
 * Example:
 *     passport.use(new VKontakteTokenStrategy({
 *           clientID: '123-456-789',
 *           clientSecret: 'shhh-its-a-secret',
 *           passReqToCallback: true
 *       }, function(req, accessToken, refreshToken, profile, next) {
 *              User.findOrCreate(..., function (error, user) {
 *                  next(error, user);
 *              });
 *          }
 *       ));
 *
 * @param {Object} _options
 * @param {Function} _verify
 * @constructor
 */
function VKontakteTokenStrategy(_options, _verify) {
  var options = _options || {};
  options.authorizationURL = options.authorizationURL || 'https://oauth.vk.com/authorize';
  options.tokenURL = options.tokenURL || 'https://oauth.vk.com/access_token';
  options.profileURL = options.profileURL || 'https://api.vk.com/method/users.get';
  options.apiVersion = options.apiVersion || '5.0';

  OAuth2Strategy.call(this, options, _verify);

  this.name = 'vkontakte-token';
  this._profileURL = options.profileURL;
  this._apiVersion = options.apiVersion;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Authenticate method
 * @param {Object} req
 * @param {Object} options
 * @returns {*}
 */
VKontakteTokenStrategy.prototype.authenticate = function (req, options) {
  var self = this;
  var accessToken = (req.body && req.body.access_token) || (req.query && req.query.access_token) || (req.headers && req.headers.access_token);
  var refreshToken = (req.body && req.body.refresh_token) || (req.query && req.query.refresh_token) || (req.headers && req.headers.refresh_token);

  if (!accessToken) {
    return self.fail({message: 'You should provide access_token'});
  }

  self._loadUserProfile(accessToken, function (error, profile) {
    if (error) return self.error(error);

    function verified(error, user, info) {
      if (error) return self.error(error);
      if (!user) return self.fail(info);

      return self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
};

/**
 * Parse user profile
 * @param {String} accessToken Vkontakte OAuth2 access token
 * @param {Function} done
 */
VKontakteTokenStrategy.prototype.userProfile = function (accessToken, done) {
  var fields = ['uid', 'first_name', 'last_name', 'screen_name', 'sex', 'photo'];
  var url = this._profileURL + '?fields=' + fields.join(',') + '&v=' + this._apiVersion;

  this._oauth2.get(url, accessToken, function (error, body, res) {
    if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

    try {
      var json = JSON.parse(body);
      if (json.error) return done(new InternalOAuthError(json.error.error_msg, json.error.error_code));

      json = json.response[0];

      var profile = {
        provider: 'vkontakte',
        id: json.id,
        username: json.screen_name,
        displayName: json.first_name + ' ' + json.last_name,
        name: {
          familyName: json.last_name || '',
          givenName: json.first_name || ''
        },
        emails: [],
        photos: [],
        _raw: body,
        _json: json
      };

      return done(null, profile);
    } catch (e) {
      return done(e);
    }
  });
};

module.exports = VKontakteTokenStrategy;

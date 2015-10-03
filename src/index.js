import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';

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
 * @param {Object} _options
 * @param {Function} _verify
 * @example
 * passport.use(new VKontakteTokenStrategy({
 *   clientID: '123456789',
 *   clientSecret: 'shhh-its-a-secret'
 * }), function(accessToken, refreshToken, profile, next) {
 *   User.findOrCreate({vkontakteId: profile.id}, function(error, user) {
 *     next(error, user);
 *   })
 * })
 */
export default class VKontakteTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {
    let options = _options || {};
    let verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://oauth.vk.com/authorize';
    options.tokenURL = options.tokenURL || 'https://oauth.vk.com/access_token';

    super(options, verify);

    this.name = 'vkontakte-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._profileFields = options.profileFields || ['uid', 'first_name', 'last_name', 'screen_name', 'sex', 'photo'];
    this._profileURL = options.profileURL || 'https://api.vk.com/method/users.get';
    this._apiVersion = options.apiVersion || '5.0';
    this._passReqToCallback = options.passReqToCallback;
  }

  /**
   * Authenticate method
   * @param {Object} req
   * @param {Object} options
   * @returns {*}
   */
  authenticate(req, options) {
    let accessToken = (req.body && req.body[this._accessTokenField]) || (req.query && req.query[this._accessTokenField]);
    let refreshToken = (req.body && req.body[this._refreshTokenField]) || (req.query && req.query[this._refreshTokenField]);

    if (!accessToken) return this.fail({message: `You should provide ${this._accessTokenField}`});

    this._loadUserProfile(accessToken, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        this._verify(accessToken, refreshToken, profile, verified);
      }
    });
  }

  /**
   * Parse user profile
   * @param {String} accessToken Vkontakte OAuth2 access token
   * @param {Function} done
   */
  userProfile(accessToken, done) {
    let url = this._profileURL + '?fields=' + this._profileFields.join(',') + '&v=' + this._apiVersion;

    this._oauth2.get(url, accessToken, (error, body, res) => {
      if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

      try {
        let json = JSON.parse(body);
        if (json.error) return done(new InternalOAuthError(json.error.error_msg, json.error.error_code));

        json = json.response[0];

        let profile = {
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
  }
}

'use strict';

const async = require.main.require('async');
const nconf = require.main.require('nconf');
const passport = require.main.require('passport');
const winston = require.main.require('winston');
const passportVK = require('passport-vkontakte').Strategy;

const authenticationController = require.main.require('./src/controllers/authentication');
const db = require.main.require('./src/database');
const meta = require.main.require('./src/meta');
const User = require.main.require('./src/user');


const constants = Object.freeze({
	'name': 'Vkontakte',
	'admin': {
		'icon': 'fa-vk',
		'route': '/plugins/sso-vkontakte'
	},

	displayName: 'VK',
  button: {
    borderColor: '#4680C2',
    backgroundColor: '#4680C2',
    textColor: '#FFF',
  },
});

const Vkontakte = {
	settings: {
		"id": process.env.SSO_VK_CLIENT_ID || undefined,
		"secret": process.env.SSO_VK_CLIENT_SECRET || undefined,
		"autoconfirm": process.env.SSO_VK_AUTOCONFIRM === "true" || false
	},
};

Vkontakte.init = function (data, callback) {
	const hostHelpers = require.main.require('./src/routes/helpers');

	function render(_, res) {
		res.render('admin/plugins/sso-vkontakte', {});
	}

	data.router.get('/admin/plugins/sso-vkontakte', data.middleware.admin.buildHeader, render);
	data.router.get('/api/admin/plugins/sso-vkontakte', render);

	hostHelpers.setupPageRoute(data.router, '/deauth/vkontakte', data.middleware, [data.middleware.requireUser], function (_, res) {
		res.render('plugins/sso-vkontakte/deauth', {
			service: '[[sso-vk:vk]]',
		});
	});
	data.router.post('/deauth/vkontakte', [data.middleware.requireUser, data.middleware.applyCSRF], function (req, res, next) {
		Vkontakte.deleteUserData({ uid: req.user.uid }, function (err) {
			if (err) {
				return next(err);
			}

			res.redirect(`${nconf.get('url')}/me/edit`);
		});
	});

	meta.settings.get('sso-vkontakte', function (_, loadedSettings) {
		if (loadedSettings.id) {
			Vkontakte.settings.id = loadedSettings.id;
		}
		if (loadedSettings.secret) {
			Vkontakte.settings.secret = loadedSettings.secret;
		}
		if (loadedSettings.autoconfirm) {
			Vkontakte.settings.autoconfirm = loadedSettings.autoconfirm === 'on';
		}
		callback();
	});
};

Vkontakte.getAssociation = function (data, callback) {
	User.getUserField(data.uid, 'vkontakteid', function (err, vkontakteid) {
		if (err) {
			return callback(err, data);
		}

		if (vkontakteid) {
			data.associations.push({
				associated: true,
				url: `https://vk.com/id${vkontakteid}`,
				deauthUrl: `${nconf.get('url')}/deauth/vkontakte`,
				name: '[[sso-vk:vk]]',
				icon: constants.admin.icon
			});
		} else {
			data.associations.push({
				associated: false,
				url: `${nconf.get('url')}/auth/vkontakte`,
				name: '[[sso-vk:vk]]',
				icon: constants.admin.icon
			});
		}

		callback(null, data);
	})
};

Vkontakte.getStrategy = function (strategies, callback) {

	if (Vkontakte.settings['id'] && Vkontakte.settings['secret']) {
		passport.use(new passportVK({
			clientID: Vkontakte.settings['id'],
			clientSecret: Vkontakte.settings['secret'],
			callbackURL: `${nconf.get('url')}/auth/vkontakte/callback`,
			passReqToCallback: true,
			profileFields: ['id', 'emails', 'name', 'displayName']
		}, function (req, _, __, ___, profile, done) {

			if (hasOwnProperty(req, 'user') && hasOwnProperty(req.user, 'uid') && req.user.uid > 0) {
				User.setUserField(req.user.uid, 'vkontakteid', profile.id);
				db.setObjectField('vkontakteid:uid', profile.id, req.user.uid);

				return authenticationController.onSuccessfulLogin(req, req.user.uid, function (err) {
					done(err, !err ? req.user : null);
				});
			}

			const email = hasOwnProperty(profile, 'emails')
				? profile.emails[0].value
				: (profile.username ? profile.username : profile.id) + '@users.noreply.vkontakte.com';

			Vkontakte.login(profile.id, profile.displayName, email, profile.photos[0].value, function (err, user) {
				if (err) {
					return done(err);
				}

				authenticationController.onSuccessfulLogin(req, user.uid, function (err) {
					done(err, !err ? user : null);
				});
			});
		}));

		strategies.push({
			name: 'vkontakte',
			url: '/auth/vkontakte',
			callbackURL: '/auth/vkontakte/callback',
			icon: 'vk fa-vk',
			scope: 'email',

      displayName: constants.displayName,
      ...constants.button
		});
	}

	callback(null, strategies);
};

Vkontakte.login = function (vkontakteID, displayName, email, picture, callback) {
	Vkontakte.getUidByVkontakteId(vkontakteID, function (err, uid) {
		if (err) {
			return callback(err);
		}

		if (uid !== null) {
			// Existing User
			callback(null, {
				uid: uid
			});
		} else {

			// New User
			const success = function (uid) {

				const autoConfirm = Vkontakte.settings && Vkontakte.settings.autoconfirm;
				User.setUserField(uid, 'email:confirmed', autoConfirm);
				if (autoConfirm) {
					db.sortedSetRemove('users:notvalidated', uid);
				}

				User.setUserField(uid, 'vkontakteid', vkontakteID);
				db.setObjectField('vkontakteid:uid', vkontakteID, uid);

				if (picture) {
					User.setUserField(uid, 'uploadedpicture', picture);
					User.setUserField(uid, 'picture', picture);
				}

				callback(null, {
					uid: uid
				});
			};

			User.getUidByEmail(email, function (err, uid) {
				if (err) {
					return callback(err);
				}

				if (!uid) {
					User.create({ username: displayName, email: email }, function (err, uid) {
						if (err) {
							return callback(err);
						}

						success(uid);
					});
				} else {
					success(uid); // Existing account -- merge
				}
			});
		}
	});
};

Vkontakte.getUidByVkontakteId = function (vkontakteID, callback) {
	db.getObjectField('vkontakteid:uid', vkontakteID, function (err, uid) {
		if (err) {
			return callback(err);
		}
		callback(null, uid);
	});
};

Vkontakte.addMenuItem = async function (custom_header) {
	custom_header.authentication.push({
		'route': constants.admin.route,
		'icon': constants.admin.icon,
		'name': '[[sso-vk:vk]]'
	});
	return custom_header;
};

Vkontakte.deleteUserData = function (user, callback) {

	const uid = user.uid;

	async.waterfall([
		async.apply(User.getUserField, uid, 'vkontakteid'),
		function (oAuthIdToDelete, next) {
			db.deleteObjectField('vkontakteid:uid', oAuthIdToDelete, next);
		},
		function (next) {
			db.deleteObjectField(`user:${uid}`, 'vkontakteid', next);
		}
	], function (err) {
		if (err) {
			winston.error(`[sso-vkontakte] Could not remove OAuthId data for uid ${uid}. Error: ${err}`);
			return callback(err);
		}
		callback(null, uid);
	});
};

function hasOwnProperty(obj, prop) {
	return Object.prototype.hasOwnProperty.call(obj, prop);
}

module.exports = Vkontakte;

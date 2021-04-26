/* global define, $, config */
'use strict'

$(window).on('action:script.load', function (ev, data) {
  data.scripts.push('sso-vk/login')
})

define('sso-vk/login', function () {
  const Login = {}

  Login.init = function () {
    const replaceEl = $('.alt-logins .vkontakte a i')
    const replacement = document.createElement('img')
    replacement.src = config.relative_path + '/plugins/@ariastel/nodebb-plugin-sso-vk/images/button_vk_login.svg'
    replaceEl.replaceWith(replacement)
  }

  return Login
})

var crypto = require('crypto'),
  _ = require('lodash'),
  appConfig = sails.config.appConfig;

module.exports = {
  getAuthenticatedUrl: getAuthenticatedUrl
};

function getAuthenticatedUrl(url, queryString, httpRequestType) {
  var updatedTimeStamp = Math.floor(Date.now() / 1000) + appConfig.expiry;
  var stringToSign = url + '?' + '&accessKey=' + appConfig.appKey;
  var authToken = getEncryptedAppString(stringToSign, appConfig.appSecret);
  if (_.includes(appConfig.domain, 'http') === false && _.includes(appConfig.domain, 'https') === false) {
    var authenticatedUrl = 'http://' + appConfig.domain + url + '?' + queryString + '&authToken=' + authToken + '&timeStamp=' + updatedTimeStamp;
  } else {
    var authenticatedUrl = appConfig.domain + url + '?' + queryString + '&authToken=' + authToken + '&timeStamp=' + updatedTimeStamp;
  }
  return authenticatedUrl;
}

function getEncryptedAppString(stringToSign, appSecret) {
  var hmac = crypto.createHmac('sha1', appSecret);
  hmac.update(stringToSign);
  return hmac.digest('hex');
}

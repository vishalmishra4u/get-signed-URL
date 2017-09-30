var crypto = require('crypto'),
  _ = require('lodash'),
  appConfig = sails.config.appConfig;

module.exports = {
  getAuthenticatedUrl: getAuthenticatedUrl
};

function getAuthenticatedUrl(url, queryString, httpRequestType) {
  var updatedTimeStamp = Math.floor(Date.now() / 1000) + appConfig.expiry;
  if(queryString !== null){
    var query = queryString + '&accessKey=' + appConfig.appKey + '&timeStamp=' + updatedTimeStamp;
  }
  else{
    var query = '&accessKey=' + appConfig.appKey + '&timeStamp=' + updatedTimeStamp;
  }
  var stringToSign = httpRequestType + url + '?' + query;
  var encryptedAppSecret = getEncryptedAppSecret(stringToSign, appConfig.appSecret);
  var authToken = bin2hex(encryptedAppSecret);
  if (_.includes(appConfig.domain, 'http') === false && _.includes(appConfig.domain, 'https') === false) {
    var authenticatedUrl = 'http://' + appConfig.domain + url + '?' + queryString + '&authToken=' + authToken;
  } else {
    var authenticatedUrl = appConfig.domain + url + '?' + queryString + '&authToken=' + authToken;
  }
  return authenticatedUrl;
}

function bin2hex(s) {
  var i, l, n;
  var o = '';
  s += '';

  for (i = 0, l = s.length; i < l; i++) {
    n = s.charCodeAt(i).toString(16);
    o += n.length < 2 ? '0' + n : n;
  }
  return o
}

function getEncryptedAppSecret(stringToSign, appSecret){
    var hmac = crypto.createHmac('sha1', appSecret);
    hmac.update(stringToSign);
    return hmac.digest('binary');
};

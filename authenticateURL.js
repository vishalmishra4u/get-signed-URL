var crypto = require('crypto'),
  _ = require('lodash');

module.exports = function getVerifiedUrl(req, res, next) {
  var completeUrl = req.originalUrl;
  var url = completeUrl.substr(0, completeUrl.indexOf('?'));
  var timeStamp = completeUrl.substr(completeUrl.lastIndexOf('=') + 1,completeUrl.length - 1);
  if(Math.floor(Date.now() / 1000) > timeStamp){
    return res.handleError({
      code : 403,
      message : 'REQUEST_EXPIRED'
    });
  }
  var stringToSign = url + '?' + '&accessKey=' + appConfig.appKey;
  var encryptedKey = getEncryptedAppString(stringToSign, appConfig.appSecret);
  var tokenString = completeUrl.substring(completeUrl.lastIndexOf('authToken'), completeUrl.lastIndexOf("&"));
  var requestToken = tokenString.substr(tokenString.indexOf('=') + 1, tokenString.length - 1);
  if(requestToken !== encryptedKey){
    return res.handleError({
      code : 403,
      message : 'USER_NOT_AUTHORISED'
    });
  }
  else{
    next();
  }
}

function getEncryptedAppString(stringToSign, appSecret){
    var hmac = crypto.createHmac('sha1', appSecret);
    hmac.update(stringToSign);
    return hmac.digest('hex');
};

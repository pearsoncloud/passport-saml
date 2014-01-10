var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');
var SignedXml = require('xml-crypto').SignedXml;

var SAML = function (options) {
  this.options = this.initialize(options);
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (!options.protocol) {
    options.protocol = 'https://';
  }

  if (!options.path) {
    options.path = '/saml/consume';
  }

  if (!options.issuer) {
    options.issuer = 'onelogin_saml';
  }

  if (options.identifierFormat === undefined) {
    options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
  }

  return options;
};

SAML.prototype.generateUniqueID = function () {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
};

SAML.prototype.generateInstant = function () {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + (date.getUTCHours()+2)).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z"; 
};

SAML.prototype.signRequest = function (xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateCert, 'base64');
}

/**
 * Insert signature into xml string at a particular element position.
 *
 * @param xml - xml string
 * @param xpath - xpath that points to element afterwhich to insert signature
 * @param key - certificate key
 * @return xml string with key inserted at element pointed by xpath.
 */
SAML.prototype.signXml = function (xml, xpath, key)
{
  /*this.idMode = idMode
  this.references = []
  this.id = 0
  this.signingKey = null
  this.signatureAlgorithm = this.options.signatureAlgorithm || "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  this.keyInfoProvider = null
  this.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
  this.signedXml = ""
  this.signatureXml = ""
  this.signatureXmlDoc = null
  this.signatureValue = ""
  this.originalXmlWithIds = ""
  this.validationErrors = []
  this.keyInfo = null
  this.idAttributes = [ 'Id', 'ID' ];*/

  var sig = new SignedXml();
  //sig.idMode = "wssecurity";
  /*sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data>"+"MIIDLDCCAhQCCQCLxCuGksVtCzANBgkqhkiG9w0BAQUFADBYMQswCQYDVQQGEwJV"+
"SzETMBEGA1UECBMKU29tZS1TdGF0ZTEQMA4GA1UEBxMHSGFsaWZheDEQMA4GA1UE"+
"ChMHbXlzdGFjazEQMA4GA1UEAxMHbXlzdGFjazAeFw0xMzExMDkwOTUyMTJaFw0x"+
"NDExMDkwOTUyMTJaMFgxCzAJBgNVBAYTAlVLMRMwEQYDVQQIEwpTb21lLVN0YXRl"+
"MRAwDgYDVQQHEwdIYWxpZmF4MRAwDgYDVQQKEwdteXN0YWNrMRAwDgYDVQQDEwdt"+
"eXN0YWNrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6JvHJpzor32"+
"9Mq1Wfp4w2GJI5lMKfLosYEJBjG1axRYQfsTU8cX9wnaBu0RPvbyKY1n5ZjCkHq3"+
"N76PU/oGln5q/IETfgEH8xUg5g/wEwMsZjNUKnP+hRBw3O0/axT8cUUaRPrN6Zx8"+
"/Rg8tfYS63NXMjhfYK0464NCoXpatmEzkFrwAaun1V42LcDwyiI/r0N6RLha7ASO"+
"Ho97o9/PsfWmDze7eOJOo4Q93Aex5YJRjvS7Pj4kYzPy78oQhzOm2WpOm7IzAwTh"+
"bFouQkVQgsQ9+XOv0sPOs80aNjAajzwfySfwXMnDjA/AOEXplsFR9hW90xO92mWT"+
"EKqtuQ7qiwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBq9UfdwUxDmhEFw2iPwUPe"+
"eF9sQpoNJpLKP3Btk9Nr6ihwTKEJfanwZZbne973DmUkWBrb0NvBWmVXvqEk4mEH"+
"43wkZjKsTHpWR8KlYedTnh5Um90FmQZChcVoSAW++AEu9IfB6tMDsvrndopBmak2"+
"MbhIERIdtVmURjt20apQJlx+QfcdPHvrBuq8dJRu5IwEkBxVlOJ5gbkSXHf9bYbr"+
"frd6EZnxzQQk0UJuMMl2rJOkl3teNi5SmH+Kz2BrxpQT0192YL1YFHLfgCrXE4aQ"+
"jUe8MXQ5vz8dK/bSFgjwcAe1RlDtPKoOYTW0aA4CAmJ8dyMSlIoMqV56URCe42ko"+"</X509Data>"
    },
    getKey: function (keyInfo) {
      return self.certToPEM(self.options.mystackCert);
    }
  };*/
  sig.signingKey = key;
  sig.addReference(xpath); 
  sig.computeSignature(xml);
  return sig.getSignedXml();
}

SAML.prototype.generateAuthorizeRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  // Post-auth destination
  if (this.options.callbackUrl) {
    callbackUrl = this.options.callbackUrl;
  } else {
    var callbackUrl = this.options.protocol + req.headers.host + this.options.path;
  }

  var request =
   "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant + 
   "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\" Destination=\"" + 
   this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

  if (this.options.identifierFormat) {
    request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat + 
    "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
  }
   
  request += 
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
    "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
  "</samlp:AuthnRequest>";

  if (this.options.privateCert) {
    request = this.signXml(request, "//*[local-name(.)='Issuer']", this.options.privateCert);
    console.log("Signed login request: "+request);
  }

  return request;
};

SAML.prototype.generateLogoutRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  //samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
  // ID="_135ad2fd-b275-4428-b5d6-3ac3361c3a7f" Version="2.0" Destination="https://idphost/adfs/ls/" 
  //IssueInstant="2008-06-03T12:59:57Z"><saml:Issuer>myhost</saml:Issuer><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" 
  //NameQualifier="https://idphost/adfs/ls/">myemail@mydomain.com</NameID<samlp:SessionIndex>_0628125f-7f95-42cc-ad8e-fde86ae90bbe
  //</samlp:SessionIndex></samlp:LogoutRequest> 

  var request = '<?xml version="1.0" encoding="UTF-8"?>' +
                '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_135ad2fd-b275-4428-b5d6-3ac3361c3a7f" Version="2.0" Destination="https://idphost/adfs/ls/" IssueInstant="2008-06-03T12:59:57Z">' +
                '<saml:Issuer>myhost</saml:Issuer>' +
                '<NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" NameQualifier="https://idphost/adfs/ls/">myemail@mydomain.com</NameID>' +
                '<samlp:SessionIndex>_0628125f-7f95-42cc-ad8e-fde86ae90bbe</samlp:SessionIndex>' +
                '</samlp:LogoutRequest>';

  if (this.options.privateCert) {
    request = this.signXml(request, "//*[local-name(.)='Issuer']", this.options.privateCert);
    console.log("Signed logout request: "+request);
  }

  return request;
}

SAML.prototype.requestToUrl = function (req, request, operation, callback) {
  var self = this;
  zlib.deflateRaw(request, function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var target = self.options.entryPoint
    var relayState = "";

    if (self.options.entryPoint.indexOf('?') == -1) {
      target += "?";
    }
    else{
      target += "&";
    }

    if (operation === 'logout') {
      if (self.options.logoutUrl) {
        target = self.options.logoutUrl;
        if (self.options.entryPoint.indexOf('?') == -1) {
          target += "?";
        }
        else{
          target += "&";
        }
      } 
    }
    if (operation === 'authorize' && req.query.RelayState){
      relayState = req.query.RelayState;  
    }

    var samlRequest = {
      SAMLRequest: base64,
      RelayState: relayState
    };

    if (self.options.privateCert) {
      samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
    }

    target += querystring.stringify(samlRequest);
    //console.log("Target - " + target);
    callback(null, target);
  });
}

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var request = this.generateAuthorizeRequest(req);
   
  this.requestToUrl(req, request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function(req, callback) {
  var request = this.generateLogoutRequest(req);

  this.requestToUrl(req, request, 'logout', callback);
}

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateSignature = function (xml, cert) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>"
    },
    getKey: function (keyInfo) {
      return self.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  } else if (parentElement['samlp:'+elementName]) {
    return parentElement['samlp:'+elementName];
  } else if (parentElement['saml2p:'+elementName]){
    return parentElement['saml2p:'+elementName];
  }else if (parentElement['saml2:'+elementName]){
    return parentElement['saml2:'+elementName];
  }
  return parentElement[elementName];
}

SAML.prototype.validateResponse = function (samlResponse, callback) {
  var self = this;
  var xml = new Buffer(samlResponse, 'base64').toString('ascii');
  var parser = new xml2js.Parser({explicitRoot:true});
  console.log(xml.toString());
  parser.parseString(xml, function (err, doc) {

    // Verify signature
    if (self.options.cert && !self.validateSignature(xml, self.options.cert)) {
      return callback(new Error('Invalid signature'), null, false);
    }

    var response = self.getElement(doc, 'Response');
    if (response) {
      var assertion = self.getElement(response, 'Assertion');
      if (!assertion) {
        return callback(new Error('Missing SAML assertion'), null, false);
      }

      profile = {};
      var issuer = self.getElement(assertion[0], 'Issuer');
      if (issuer) {
        profile.issuer = issuer[0];
      }

      var subject = self.getElement(assertion[0], 'Subject');
      if (subject) {
        var nameID = self.getElement(subject[0], 'NameID');
        if (nameID) {
            profile.nameID = nameID[0]["_"];

          if (nameID[0]['$'].Format) {
            profile.nameIDFormat = nameID[0]['$'].Format;
          }
        }
      }

      var attributeStatement = self.getElement(assertion[0], 'AttributeStatement');
      if (!attributeStatement) {
        return callback(new Error('Missing AttributeStatement'), null, false);
      }

      var attributes = self.getElement(attributeStatement[0], 'Attribute');

      if (attributes) {
        attributes.forEach(function (attribute) {
          var value = self.getElement(attribute, 'AttributeValue');
          profile[attribute['$'].Name] = "";
          value.forEach(function(attributeValue){
            if (typeof attributeValue === 'string') {
              profile[attribute['$'].Name] += attributeValue + ";";
            } else {
              profile[attribute['$'].Name] += attributeValue['_'] + ";";
            }
          });
          profile[attribute['$'].Name] = profile[attribute['$'].Name].substring(0,profile[attribute['$'].Name].length-1);
        });
      }

      // Sets isSuperAdmin to true if user profile includes a super admin or org creator
      if (typeof profile.isSuper === 'string' && profile.isSuper.indexOf("myStackSuperAdmins") >= 0)
        profile.isSuperAdmin = true;
      else
        profile.isSuperAdmin = false;
        

      if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
        // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
        profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
      }

      if (!profile.email && profile.mail) {
        profile.email = profile.mail;
      }

      callback(null, profile, false);
    } else {
      var logoutResponse = self.getElement(doc, 'LogoutResponse');

      if (logoutResponse){
        callback(null, null, true);
      } else {
        return callback(new Error('Unknown SAML response message'), null, false);
      }

    }


  });
};

exports.SAML = SAML;
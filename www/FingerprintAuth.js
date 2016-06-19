function FingerprintAuth() {
}

FingerprintAuth.prototype.show = function (params, successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "authenticate", // action
        [ // Array of arguments to pass to the Java class
            {
                clientId: params.clientId,
                clientSecret: params.clientSecret
            }
        ]
    );
}


FingerprintAuth.prototype.setUser = function (user_pin, successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "setpin", // action
        [ // Array of arguments to pass to the Java class
            {
                pin: user_pin,

            }
        ]
    );
}

FingerprintAuth.prototype.getUser = function (user_pin, successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "getuser", // action
        [ // Array of arguments to pass to the Java class
            {
                user_data: user_pin,

            }
        ]
    );
}

FingerprintAuth.prototype.isAvailable = function (successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "availability", // action
        [{}]
    );
}


FingerprintAuth.prototype.isPin = function (successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "checkpin", // action
        [{}]
    );
}

FingerprintAuth = new FingerprintAuth();
module.exports = FingerprintAuth;
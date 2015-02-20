// **************** Callbacks ****************
var _authSuccessCallback = null;
var _authErrorCallback = null;

// **************** Exceptions ****************
function SecurityException(message) {
    this.message = message;
    this.name = "SecurityException";
}

// ***
// **************** API ****************
// ***

// **************** Value-added Functions ****************
// Get an access token 
function GetCurrentAccessToken() {
    var accessToken = GetAccessTokenFromStorage();
    if (accessToken === null) {
        var refreshToken = GetRefreshTokenFromStorage();
        if (refreshToken != null) {
            GetTokensForRefreshToken(_authSuccessCallback, _authErrorCallback);
            return GetAccessTokenFromStorage();
        }
        else {
            return null; //no valid refresh token found, a re-login is required
        }
    }
    else
        return accessToken;
}

// Clear the tokens to "log out" the user
function ClearTokens() {
    ClearAccessTokenInfo();
    ClearRefreshTokenInfo();
}

// Clear access token information
function ClearAccessTokenInfo() {
    if (typeof (Storage) !== "undefined") {
        //localStorage and sessionStorage support is in the browser so use that
        lscache.remove("accessToken");
        lscache.remove("accessTokenExpiration");
    }
    else {
        // Remove cookies
        ClearCookie("accessToken");
        ClearCookie("accessTokenExpiration");
    }
}

// Clear refresh token information
function ClearRefreshTokenInfo() {
    if (typeof (Storage) !== "undefined") {
        lscache.remove("refreshToken");
    }
    else {
        ClearCookie("refreshToken");
    }
}

// **************** Token management ****************

// Get a token for user credentials and call the callback in success or error conditions
function GetTokensForCredentials(clientId, clientSecret, userName, password, successCallback, errorCallback) {
    _authSuccessCallback = successCallback;
    _authErrorCallback = errorCallback;
    var xhr = createCORSRequest('POST', 'https://' + Configuration.hostName + "/" + Configuration.accessTokenUrl, false, HandleTokenResponse, ErrorGettingTokens);
    var data = '{"client_id":"' + clientId +
                '","client_secret":"' + clientSecret +
                '","grant_type":"password","password":"' + password +
                '","username":"' + userName + '"}';
    //Send the proper header information along with the request
    xhr.setRequestHeader("Content-type", "application/json");
    xhr.setRequestHeader("Content-length", data.length);
    xhr.send(data);
}

// Get a and updated access and refresh token using the current refresh token and call the callback in success or error conditions
function GetTokensForRefreshToken(successCallback, errorCallback) {
    _authSuccessCallback = successCallback;
    _authErrorCallback = errorCallback;
    var xhr = createCORSRequest('POST', 'https://' + Configuration.hostName + "/" + Configuration.refreshAccessTokenUrl, false, HandleTokenResponse, ErrorGettingTokens);
    var refreshToken = GetRefreshTokenFromStorage();
    if(refreshToken != null)
    {
        var data = '{"grant_type":"refresh_token","refresh_token":"' + refreshToken + '"}';
        //Send the proper header information along with the request
        xhr.setRequestHeader("Content-type", "application/json");
        xhr.setRequestHeader("Content-length", data.length);
        xhr.send(data);
    }
}

// Token Management success call back
function HandleTokenResponse(xhr) {
    var json = JSON.parse(xhr.responseText);
    if (json.access_token != null) {
        var accessToken = json.access_token;
        var refreshToken = json.refresh_token;
        var accessTokenExpiration = json.expires_in;
        SetTokensInStorage(accessToken, refreshToken, accessTokenExpiration);
        _authSuccessCallback();
    }
    else if (json.error != null) { // call succeeded but error in response
        ClearTokens();
        ErrorGettingTokens(xhr);
    }
}

// Token Management error call back
function ErrorGettingTokens(xhr) {
    var secEx = null;
    var reAuthRequired = false;
    var errorResponse = JSON.parse(xhr.responseText);
    if (xhr.status == 403 && errorResponse.ErrorCode != null && errorResponse.ErrorCode == 1401) // TokenExpiredException
    {
        // try to get a new one if we have a refresh token
        var refreshToken = GetRefreshTokenFromStorage();
        if (refreshToken != null) {
            GetTokensForRefreshToken(false);
        }
        else {
            // no refresh token was found, this requires a clean login to continue
            secEx = new SecurityException("No refresh token is available to renew the access token.");
            reAuthRequired = true;
        }
    }
    else {
        // an authentication or system error occured
        var message = GetOAuthResponseErrorTypeText(errorResponse.error);
        secEx = new SecurityException(message);
    }
    _authErrorCallback(secEx, reAuthRequired);
}

// Retrieve an access token from the cache/cookie
function GetAccessTokenFromStorage() {
    var accessToken = null;
    if (typeof (Storage) !== "undefined") {
        return lscache.get('accessToken');
    }
    else {
        return GetCookie("accessToken");
    }
    return null;
}

// Retrieve a refresh token from the cache/cookie
function GetRefreshTokenFromStorage() {
    var accessToken = null;
    if (typeof (Storage) !== "undefined") {
        return lscache.get('refreshToken');
    }
    else {
        return GetCookie("refreshToken");
    }
    return null;
}

// Retrieve a expiration of an access token from the cache/cookie
function GetAccessTokenExpirationFromStorage() {
    var accessToken = null;
    if (typeof (Storage) !== "undefined") {
        return lscache.get('accessTokenExpiration');
    }
    else {
        return GetCookie("accessTokenExpiration");
    }
    return null;
}

// Save the access/refresh token information to the cache/cookie
function SetTokensInStorage(accessToken, refreshToken, accessTokenExpiration) {
    if (typeof (Storage) !== "undefined") {
        var expirationInMinutes = (accessTokenExpiration / 60);
        var refreshExpirationInMinutes = 24 * 60 * 5; // 5 days
        lscache.set('accessToken', accessToken, expirationInMinutes);
        lscache.set('refreshToken', refreshToken, refreshExpirationInMinutes);
        lscache.set('accessTokenExpiration', accessTokenExpiration, expirationInMinutes);
    }
    else {
        // Add it as a cookie as localstorage isn't supported
        var expirationInDays = ((accessTokenExpiration / 60) / 24) ;
        SetCookie("accessToken", accessToken, expirationInDays);
        SetCookie("refreshToken", refreshToken, 5);  // 5 day duration
        SetCookie("accessTokenExpiration", refreshToken, expirationInDays);  // 5 day duration
    }
}


// **************** Cookie management ****************
function SetCookie(cookieName, value, expirationInDays) {
    var exdate = new Date();
    exdate.setDate(exdate.getDate() + expirationInDays);
    var expirationAndValue = escape(value) + ((expirationInDays == null) ? "" : "; expires=" + exdate.toUTCString());
    document.cookie = cookieName + "=" + expirationAndValue;
}

function GetCookie(cookieName) {
    var cookies = document.cookie.split(";");
    for (var i = 0; i < cookies.length; i++) {
        var x = cookies[i].substr(0, cookies[i].indexOf("="));
        var y = cookies[i].substr(cookies[i].indexOf("=") + 1);
        x = x.replace(/^\s+|\s+$/g, "");
        if (x == cookieName) {
            return unescape(y);
        }
    }
    return null;
}

function ClearCookie(cookieName)
{
    SetCookie(cookieName, "", -1);  // set to the past so it is expired
}

// **************** OAuth errors ****************

var OAuthResponseErrorType = {
    invalid_request: "The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.",
    unauthorized_client: "The client is not authorized to request an access token using this method.",
    access_denied: "The resource owner or authorization server denied the request.",
    unsupported_response_type: "The authorization server does not support obtaining an access token using this method.",
    invalid_scope: "The requested scope is invalid, unknown, or malformed.",
    server_error: "The authorization server encountered an unexpected condition which prevented it from fulfilling the request.",
    temporarily_unavailable: "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."
};

function GetOAuthResponseErrorTypeText(oauthResponseError) {
    var message = oauthResponseError;
    switch (oauthResponseError) {
        case "invalid_request":
            message = OAuthResponseErrorType.invalid_request;
            break;
        case "unauthorized_client":
            message = OAuthResponseErrorType.unauthorized_client;
            break;
        case "access_denied":
            message = OAuthResponseErrorType.access_denied;
            break;
        case "unsupported_response_type":
            message = OAuthResponseErrorType.unsupported_response_type;
            break;
        case "invalid_scope":
            message = OAuthResponseErrorType.invalid_scope;
            break;
        case "server_error":
            message = OAuthResponseErrorType.server_error;
            break;
        case "temporarily_unavailable":
            message = OAuthResponseErrorType.temporarily_unavailable;
            break;
        default:
            message = oauthResponseError;
            break;
    }
    return message;
}

// **************** CORS request support ****************

function createCORSRequest(method, url, async, callback, errorCallback) {
    var xhr = new XMLHttpRequest();
    if ("withCredentials" in xhr) {
        // Check if the XMLHttpRequest object has a "withCredentials" property.
        // "withCredentials" only exists on XMLHTTPRequest2 objects.
        xhr.open(method, url, async);
    } else if (typeof XDomainRequest != "undefined") {
        // Otherwise, check if XDomainRequest.
        // XDomainRequest only exists in IE, and is IE's way of making CORS requests.
        xhr = new XDomainRequest();
        xhr.open(method, url, async);
    } else {
        // Otherwise, CORS is not supported by the browser.
        xhr = null;
    }

    if (!xhr) {
        throw new Error('CORS not supported');
    }

    var requestTimer = setTimeout(function () {
        xhr.abort();
        errorCallback(xhr);
    }, Configuration.requestTimeout);

    xhr.onerror = function () {
        errorCallback(xhr);
    };
    xhr.onload = function () {
        callback(xhr);
    };

    xhr.onreadystatechange = function () {
        if (xhr.readyState != 4) {
            return; 
        }
        clearTimeout(requestTimer);
    }

    return xhr;
}

/**
https://github.com/pamelafox/lscache
* lscache library
* Copyright (c) 2011, Pamela Fox
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*       http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/*jshint undef:true, browser:true */

/**
* Creates a namespace for the lscache functions.
*/
var lscache = function () {

    // Prefix for all lscache keys
    var CACHE_PREFIX = 'lscache-';

    // Suffix for the key name on the expiration items in localStorage
    var CACHE_SUFFIX = '-cacheexpiration';

    // expiration date radix (set to Base-36 for most space savings)
    var EXPIRY_RADIX = 10;

    // time resolution in minutes
    var EXPIRY_UNITS = 60 * 1000;

    // ECMAScript max Date (epoch + 1e8 days)
    var MAX_DATE = Math.floor(8.64e15 / EXPIRY_UNITS);

    var cachedStorage;
    var cachedJSON;
    var cacheBucket = '';

    // Determines if localStorage is supported in the browser;
    // result is cached for better performance instead of being run each time.
    // Feature detection is based on how Modernizr does it;
    // it's not straightforward due to FF4 issues.
    // It's not run at parse-time as it takes 200ms in Android.
    function supportsStorage() {
        var key = '__lscachetest__';
        var value = key;

        if (cachedStorage !== undefined) {
            return cachedStorage;
        }

        try {
            setItem(key, value);
            removeItem(key);
            cachedStorage = true;
        } catch (exc) {
            cachedStorage = false;
        }
        return cachedStorage;
    }

    // Determines if native JSON (de-)serialization is supported in the browser.
    function supportsJSON() {
        /*jshint eqnull:true */
        if (cachedJSON === undefined) {
            cachedJSON = (window.JSON != null);
        }
        return cachedJSON;
    }

    /**
    * Returns the full string for the localStorage expiration item.
    * @param {String} key
    * @return {string}
    */
    function expirationKey(key) {
        return key + CACHE_SUFFIX;
    }

    /**
    * Returns the number of minutes since the epoch.
    * @return {number}
    */
    function currentTime() {
        return Math.floor((new Date().getTime()) / EXPIRY_UNITS);
    }

    /**
    * Wrapper functions for localStorage methods
    */

    function getItem(key) {
        return localStorage.getItem(CACHE_PREFIX + cacheBucket + key);
    }

    function setItem(key, value) {
        // Fix for iPad issue - sometimes throws QUOTA_EXCEEDED_ERR on setItem.
        localStorage.removeItem(CACHE_PREFIX + cacheBucket + key);
        localStorage.setItem(CACHE_PREFIX + cacheBucket + key, value);
    }

    function removeItem(key) {
        localStorage.removeItem(CACHE_PREFIX + cacheBucket + key);
    }

    return {

        /**
        * Stores the value in localStorage. Expires after specified number of minutes.
        * @param {string} key
        * @param {Object|string} value
        * @param {number} time
        */
        set: function (key, value, time) {
            if (!supportsStorage()) return;

            // If we don't get a string value, try to stringify
            // In future, localStorage may properly support storing non-strings
            // and this can be removed.
            if (typeof value !== 'string') {
                if (!supportsJSON()) return;
                try {
                    value = JSON.stringify(value);
                } catch (e) {
                    // Sometimes we can't stringify due to circular refs
                    // in complex objects, so we won't bother storing then.
                    return;
                }
            }

            try {
                setItem(key, value);
            } catch (e) {
                if (e.name === 'QUOTA_EXCEEDED_ERR' || e.name === 'NS_ERROR_DOM_QUOTA_REACHED') {
                    // If we exceeded the quota, then we will sort
                    // by the expire time, and then remove the N oldest
                    var storedKeys = [];
                    var storedKey;
                    for (var i = 0; i < localStorage.length; i++) {
                        storedKey = localStorage.key(i);

                        if (storedKey.indexOf(CACHE_PREFIX + cacheBucket) === 0 && storedKey.indexOf(CACHE_SUFFIX) < 0) {
                            var mainKey = storedKey.substr((CACHE_PREFIX + cacheBucket).length);
                            var exprKey = expirationKey(mainKey);
                            var expiration = getItem(exprKey);
                            if (expiration) {
                                expiration = parseInt(expiration, EXPIRY_RADIX);
                            } else {
                                // TODO: Store date added for non-expiring items for smarter removal
                                expiration = MAX_DATE;
                            }
                            storedKeys.push({
                                key: mainKey,
                                size: (getItem(mainKey) || '').length,
                                expiration: expiration
                            });
                        }
                    }
                    // Sorts the keys with oldest expiration time last
                    storedKeys.sort(function (a, b) { return (b.expiration - a.expiration); });

                    var targetSize = (value || '').length;
                    while (storedKeys.length && targetSize > 0) {
                        storedKey = storedKeys.pop();
                        removeItem(storedKey.key);
                        removeItem(expirationKey(storedKey.key));
                        targetSize -= storedKey.size;
                    }
                    try {
                        setItem(key, value);
                    } catch (e) {
                        // value may be larger than total quota
                        return;
                    }
                } else {
                    // If it was some other error, just give up.
                    return;
                }
            }

            // If a time is specified, store expiration info in localStorage
            if (time) {
                setItem(expirationKey(key), (currentTime() + time).toString(EXPIRY_RADIX));
            } else {
                // In case they previously set a time, remove that info from localStorage.
                removeItem(expirationKey(key));
            }
        },

        /**
        * Retrieves specified value from localStorage, if not expired.
        * @param {string} key
        * @return {string|Object}
        */
        get: function (key) {
            if (!supportsStorage()) return null;

            // Return the de-serialized item if not expired
            var exprKey = expirationKey(key);
            var expr = getItem(exprKey);

            if (expr) {
                var expirationTime = parseInt(expr, EXPIRY_RADIX);

                // Check if we should actually kick item out of storage
                if (currentTime() >= expirationTime) {
                    removeItem(key);
                    removeItem(exprKey);
                    return null;
                }
            }

            // Tries to de-serialize stored value if its an object, and returns the normal value otherwise.
            var value = getItem(key);
            if (!value || !supportsJSON()) {
                return value;
            }

            try {
                // We can't tell if its JSON or a string, so we try to parse
                return JSON.parse(value);
            } catch (e) {
                // If we can't parse, it's probably because it isn't an object
                return value;
            }
        },

        /**
        * Removes a value from localStorage.
        * Equivalent to 'delete' in memcache, but that's a keyword in JS.
        * @param {string} key
        */
        remove: function (key) {
            if (!supportsStorage()) return null;
            removeItem(key);
            removeItem(expirationKey(key));
        },

        /**
        * Returns whether local storage is supported.
        * Currently exposed for testing purposes.
        * @return {boolean}
        */
        supported: function () {
            return supportsStorage();
        },

        /**
        * Flushes all lscache items and expiry markers without affecting rest of localStorage
        */
        flush: function () {
            if (!supportsStorage()) return;

            // Loop in reverse as removing items will change indices of tail
            for (var i = localStorage.length - 1; i >= 0; --i) {
                var key = localStorage.key(i);
                if (key.indexOf(CACHE_PREFIX + cacheBucket) === 0) {
                    localStorage.removeItem(key);
                }
            }
        },

        /**
        * Appends CACHE_PREFIX so lscache will partition data in to different buckets.
        * @param {string} bucket
        */
        setBucket: function (bucket) {
            cacheBucket = bucket;
        },

        /**
        * Resets the string being appended to CACHE_PREFIX so lscache will use the default storage behavior.
        */
        resetBucket: function () {
            cacheBucket = '';
        }
    };
} ();
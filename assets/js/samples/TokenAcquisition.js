var _lastServiceCallFunction = '';

// Execute a login (request for tokens) and return a success/failure status to the calling page/module
function Login() {
    ExecuteLogin();

    var accessToken = GetAccessTokenFromStorage();
    if (accessToken != null) {
        return true;
    }
    return false;
}

// Calls the token management function to retrieve and cache an access token and refresh token.
// Callbacks for both success and failure are supported
function ExecuteLogin() {
    var clientId = Configuration.clientId;
    var clientSecret = Configuration.clientSecret;
    var userName = Configuration.userName;
    var password = Configuration.password;

    GetTokensForCredentials(clientId, clientSecret, userName, password, TokenManagementSuccess, TokenManagementFailure);
}

// Called when the login succeeds
function TokenManagementSuccess() {
    // nothing relevant in this example
}

// Called when the login fails
function TokenManagementFailure(e, reAuthRequired) {
    if (reAuthRequired) {
        // we reach here when a refresh is not possible or fails
        ReLoginAndRunServiceCall();
    } else {
        // all other authentication problems reach here where there is no automated retry
        $("#output").text('Failed to authenticate with this message: ' + e.message); 
    }
}

// Used to re-run a login and then call the last service method that halted due to the need for a login
function ReLoginAndRunServiceCall() {
    var success = Login();

    if (success) {
        if (_lastServiceCallFunction != null) {
            // Run the last function that required a re-login
            var fn = window[_lastServiceCallFunction];
            if (typeof fn === "function") fn();
        }
    }
}

// Removes all tokens from the cache forcing a login to be required for future access
function Logout() {
    ClearTokens();
}

// Example of a service call, in this case a Location Search
function SampleServiceCall() {
    var hostname = Configuration.hostName;
    var sampleURL = Configuration.cloudServiceURL;

    // Get the name of the current function. This is used if re-login is needed, which happens automatically, allowing control to be returned to this function
    _lastServiceCallFunction = arguments.callee.name.toString(); 

    var accessToken = GetCurrentAccessToken();
    if (accessToken != null) {
        var acceptHeader = Configuration.jsonAcceptHeader;
        var url = 'http://' + hostname + '/' + sampleURL;
        var xhr = createCORSRequest('POST', url, false, SuccessResponse, ErrorResponse);

        // send the OAuth header along with the request
        xhr.setRequestHeader("Authorization", "OAuth " + accessToken);

        xhr.setRequestHeader("Accept", acceptHeader);
        xhr.send();
    } else {
        // We got here because neither the access or refresh token was available or valid
        ReLoginAndRunServiceCall();
    }
}

// This function receives the callback when the service request in SampleServiceCall succeeds
// In this case the for each of the entities returned in the Location Search a list item showing the entity Name property is created 
function SuccessResponse(xhr) {
    $("#output").text('');

    var outData = JSON.parse(xhr.responseText);

    var $outText = $('#output');
    $.each(outData, function () {
        $('<li>' + this.Name + '</li>').appendTo($outText);
    });
}

// This function receives the callback when the service request in SampleServiceCall throws and error
function ErrorResponse(xhr) {
    $("#output").text('Failed to make the service call with status: ' + xhr.status + ' and response: ' + xhr.responseText);
}
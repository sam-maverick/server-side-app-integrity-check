import { LogMe } from '../serverLibrary';
import { PARAM_LOGGING_LEVEL } from '../parameters';

var attestcheckerlibrary;


export async function Initialize() {
    attestcheckerlibrary = await import('server-side-app-integrity-check');
}

/**
 * Android check Endpoint.
 * 'token' is the token the client received from the PlayIntegrity Server in the previous step
 * 'checkMode' is 'google' or 'server'. Set to 'server' to check integrity locally. Set to 'google' to offload the check to Google servers
 * 'nonce_truth' is the ground truth of the nonce as stored by the app server
 * 'requestType' is classic or standard
 */
export async function CheckPlayIntegrity(token, nonce_truth, checkMode, requestType) {

    LogMe(0, 'CheckPlayIntegrity(): Started');

    //var attestcheckerlibrary = await import('server-side-app-integrity-check');

    // get decrypted token
    let decryptedToken = undefined;
    try {
        LogMe(0, 'CheckPlayIntegrity(): Decrypting token');
        decryptedToken = await attestcheckerlibrary.decryptPlayIntegrity(token, checkMode);
        LogMe(0, 'CheckPlayIntegrity(): Token decrypted');
    } catch(e)  {
        LogMe(1, e.message);
        if (PARAM_LOGGING_LEVEL>=2) {
            return {status: "error", message: e.message};
        } else {
            return {status: "error", message: 'An exception has occurred when processing the token. Contact support for them to check server logs.'};
        }
    }

    LogMe(2, 'Decrypted token is: '+JSON.stringify(decryptedToken));

    let attestationresult = undefined;
    try {
        LogMe(0, 'CheckPlayIntegrity(): Verifying token');
        attestationresult = attestcheckerlibrary.verifyPlayIntegrity(decryptedToken, nonce_truth, requestType);
        LogMe(0, 'CheckPlayIntegrity(): Token verified');
    } catch(e)  {
        LogMe(1, e.message);
        if (PARAM_LOGGING_LEVEL>=2) {
            return {status: "error", message: e.message};
        } else {
            return {status: "error", message: 'An exception has occurred when processing the token. Contact support for them to check server logs.'};
        }
    }

    // send attestation result
    LogMe(0, 'CheckPlayIntegrity(): Finished');
    return attestationresult;
}

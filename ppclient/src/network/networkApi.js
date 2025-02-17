import { PARAM_SERVER_API_URL } from '../parameters.js';
import { ErrorAlert, LogMe } from '../myGeneralLibrary.jsx';

const POST_HEADERS = {
    method: 'POST',
    headers: {
        'Content-type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': 0
    },
};


export async function ApiReportMaterialToServer(pictureID) {

    LogMe(1, 'API: ApiReportMaterialToServer');

    return fetch(`${PARAM_SERVER_API_URL}/attestations/reportMaterial`, {
        ...POST_HEADERS,
        body: JSON.stringify({
            pictureID: pictureID,
        }),
    })
    .then((res) => res.json())
    .then((res) => res)

}


export async function ApiSubmitAttestationTokensToServer(environment, cookie, platformType, platformVersion, tokensArray, requestDataObject) {

    LogMe(1, 'API: ApiSubmitAttestationTokensToServer');

    return fetch(`${PARAM_SERVER_API_URL}/attestations/submitAttestationTokenToServer`, {
        ...POST_HEADERS,
        body: JSON.stringify({
            cookie: cookie, 
            environment: environment, 
            platformVersion: platformVersion, 
            platformType: platformType, 
            subrequests: tokensArray,
            requestDataObject: requestDataObject,
        }),
    })
    .then((res) => res.json())
    .then((res) => res)

}


export async function ApiGetNonceFromServer(cookie, platformType, requestType) {

    LogMe(1, 'API: ApiGetNonceFromServer');
    LogMe(1, 'API: ApiGetNonceFromServer, cookie='+cookie);

    return fetch(`${PARAM_SERVER_API_URL}/attestations/getNonceFromServer`, {
        ...POST_HEADERS,
        body: JSON.stringify({cookie, platformType, requestType}),
    })
    .then((res) => res.json())
    .then((res) => res)
}


export async function ApiTestNetworkConnection() {

    LogMe(1, 'API: ApiTestNetworkConnection');

    return fetch(`${PARAM_SERVER_API_URL}/test/doNothing`, {
        ...POST_HEADERS,
        body: JSON.stringify({}),
    })
    .then((res) => res.json())
    .then((res) => res)
}

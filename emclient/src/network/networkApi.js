import { PARAM_SERVER_API_URL } from '../parameters.js';
import { ErrorAlert, LogMe } from '../myGeneralLibrary.jsx';


const POST_HEADERS = {
    method: 'POST',
    headers: {
        'Content-type': 'application/json',
    },
};



export async function ApiReceiveMessage(cookie) {
    LogMe(1, 'ApiReceiveMessage()');;
    return fetch(`${PARAM_SERVER_API_URL}/messages/receiveMessage`, {
        ...POST_HEADERS,
        body: JSON.stringify({cookie}),
    })
    .then((res) => res.json())
    .then((res) => res)
}



export async function ApiSendMessage(cookie, recipient, message) {
// message is of the form [{}] although we will only handle simple messages with one object
// contents only applies to pictures; it is the base64 content of the file image

    return fetch(`${PARAM_SERVER_API_URL}/messages/sendMessage`, {
        ...POST_HEADERS,
        body: JSON.stringify({cookie, recipient, message}),
    })
    .then((res) => res.json())
    .then((res) => res)
}


export async function ApiResetFactoryDB() {

    LogMe(1, 'API: ApiResetDB');

    return fetch(`${PARAM_SERVER_API_URL}/administration/resetFactoryDB`, {
        ...POST_HEADERS,
    })
    .then((res) => res.json())
    .then((res) => res)
}


export async function ApiCreateAccount(username) {

    LogMe(1, 'API: ApiCreateAccount');

    return fetch(`${PARAM_SERVER_API_URL}/accounts/createAccount`, {
        ...POST_HEADERS,
        body: JSON.stringify({username}),
    })
    .then((res) => res.json())
    .then((res) => res)
}

export async function ApiCheckAccount(cookie) {

    LogMe(1, 'API: ApiCheckAccount');

    return fetch(`${PARAM_SERVER_API_URL}/accounts/checkAccount`, {
        ...POST_HEADERS,
        body: JSON.stringify({cookie}),
    })
    .then((res) => res.json())
    .then((res) => res)
}


export async function ApiGetAccountsList(cookie) {

    LogMe(1, 'API: ApiGetAccountsList');

    return fetch(`${PARAM_SERVER_API_URL}/accounts/getAccountsList`, {
        ...POST_HEADERS,
        body: JSON.stringify({cookie}),
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

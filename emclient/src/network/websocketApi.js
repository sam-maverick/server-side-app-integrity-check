import io from 'socket.io-client';

import { PARAM_SERVER_WS_URL } from '../parameters.js';
import { ErrorAlert, LogMe } from '../myGeneralLibrary.jsx';


let mysocket = null;


export async function WsApiEmitSomething(mycommand, mydata) {
    LogMe(1, 'WS: send message of ' + mycommand);
    LogMe(2, '  with data: #' + JSON.stringify(mydata)+'#');
    mysocket.emit(mycommand, {myclientdata: mydata});
}



export async function WsApiHandleReception(mycommand, MyDataHandler) {
    mysocket.on(mycommand, (data) => {
        LogMe(1, 'WS: handle message of ' + mycommand);
        MyDataHandler(data.myserverdata);
    });
}


export async function MyWebsocketConnect(mycookie, MyWebsocketOnOpen, MyWebsocketOnClose) {

    LogMe(1, 'WS: MyWebsocketConnect');

    mysocket = io(PARAM_SERVER_WS_URL, {
        transports: ['websocket'],
        auth: {
          mycookie,
        },
    });  

    mysocket.io.on("open", () => MyWebsocketOnOpen());
    mysocket.io.on("close", () => MyWebsocketOnClose());
  
}

export async function MyWebsocketDisconnect() {
    if (mysocket != null) {
        LogMe(1, 'WS: MyWebsocketDisconnect');
        mysocket.disconnect();
        mysocket.removeAllListeners();
    } else {
        LogMe(1, 'WS: MyWebsocketDisconnect could not be completed because the socket is null');   
    }
}


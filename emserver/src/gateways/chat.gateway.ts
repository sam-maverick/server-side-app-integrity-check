import { Server, Socket } from 'socket.io';
import { OnGatewayConnection, OnGatewayDisconnect, OnGatewayInit, SubscribeMessage, WebSocketGateway, WebSocketServer, MessageBody, ConnectedSocket, WsResponse } from '@nestjs/websockets';

import { PARAM_WEBSOCKET_PORT } from '../parameters';
import { LogMe } from '../serverLibrary';
import UsersModel from '../middleware/database/schemas/user';


@WebSocketGateway(
    PARAM_WEBSOCKET_PORT,
    { 
        cors: {
            origin: '*',
        }, 
        transports: ['websocket'],
    }
)
//CORS: Allow any origin, so as to allow websocket from local HTML file. Not suitable for production!


export class ChatGateway
implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect {

    @WebSocketServer() server: Server;
    private connectedUsers: { socketId: string; username: string }[] = [];

    afterInit() {
      LogMe(1, 'WS: Websocket server is initialized');    
    }
  

    async checkUserCookie (somecookie) {
    // Check if cookie exists, and if so, get the username  
        const requesteruser = await UsersModel.findOne({'cookie': somecookie });

        if (requesteruser) {
            return requesteruser.username;
        } else {
            LogMe(1, 'checkUserCookie(): This cookie does not exist: ' + somecookie);   
            return false;
        }    
    }  

    async handleConnection(client: Socket) {
        LogMe(1, 'WS: handleConnection');
        const receivedCookie = client.handshake.auth.mycookie;
        const clientSocketId = client.id;

        // check cookie
        let identifiedUsername = await this.checkUserCookie(receivedCookie);
        if (! identifiedUsername) {
            client.emit('error', {myserverdata: 'Cookie not found on the server.'});
            return;
        }    

        // Check if the user is already in our list of connected users
        const existingUserConnection = this.connectedUsers?.filter(
            (u) => u.username === identifiedUsername,
        )[0];

        if (existingUserConnection) {
            // If already on the list, updated clientSocketId
            existingUserConnection.socketId = clientSocketId;
        } else {
            // If not, add it to the list
            this.connectedUsers?.push( {socketId: clientSocketId, username: identifiedUsername,} );
        }

        LogMe(1, `User ${client.id} has connected`);
    }


    async handleDisconnect(client: Socket) {
        LogMe(1, 'WS: handleDisconnect');
        LogMe(1, `User ${client.id} has disconnected`);
    }


    @SubscribeMessage('ping')
    async handlePingMessage (@MessageBody() data: any, @ConnectedSocket() client: Socket) {
        LogMe(1, 'WS: handleMessage of ping');
        LogMe(2, '#'+JSON.stringify(data['myclientdata'])+'#');

        return {
            event: 'pong',
            data: {myserverdata: '** This is data from the server'},
        };
    }


    @SubscribeMessage('clientNotificationNewMessage')
    async handleClientNotificationNewMessage (@MessageBody() data: any, @ConnectedSocket() client: Socket) {
        LogMe(1, 'WS: handleMessage of clientNotificationNewMessage');
        LogMe(2, '#'+JSON.stringify(data['myclientdata'])+'#');

        // Check cookie
        let senderUsername = await this.checkUserCookie(data['myclientdata']['emitterCookie']);
        if (! senderUsername) {
            client.emit('error', {myserverdata: 'Cookie not found on the server.'});
            return;
        }    

        // Check if the receiver user is already in our list of connected users
        const existingUserConnection = this.connectedUsers?.filter(
            (u) => u.username === data['myclientdata']['receiverUsername'],
        )[0];

        if (existingUserConnection) {
            // If connected, notify it
            LogMe(1, 'WS: Sending new message notification to ' + data['myclientdata']['receiverUsername']);
            // Only notify the recipient of the message
            this.server.to(existingUserConnection.socketId).emit('serverNotificationNewMessage', {myserverdata: {fromUser: senderUsername}});
        } else {
            LogMe(1, 'WS: ' + data['myclientdata']['receiverUsername'] + ' is not connected, so it will not be notified');
        }
    }

}

import { Controller, Post, Req } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';

import { AppService } from '../app.service';
import UsersModel from '../middleware/database/schemas/user';
import MessagesModel from '../middleware/database/schemas/message';
import { LogMe } from '../serverLibrary';


@Controller('messages')
export class MessageController {
    constructor(private readonly appService: AppService) {}

    @Post('/sendMessage')
    async sendMessage(@Req() req) {

        LogMe(1, 'Controller: messages/sendMessage');    

        const cookie: string = req.body.cookie;

        const userSender = await UsersModel.findOne({'cookie': cookie });

        if(userSender) {

            const newMessageDocument = {
                sender: userSender.username,
                recipient: req.body.recipient,
                message : req.body.message,
            };

            const message = await MessagesModel.create(newMessageDocument);
            
            if(message) {
                return {
                    isSuccessful: true,
                    resultMessage: 'Message queued successfully.',
                };
            } else {
                return {
                    isSuccessful: false,
                    resultMessage: 'There has been an error.',
                };
            }
        } else {

            return {
                isSuccessful: false,
                resultMessage: 'Cookie not found on the server.',     
            };
        }

    }

    @Post('/receiveMessage')
    async receiveMessage(@Req() req) {

        LogMe(1, 'Controller: messages/receiveMessage');    
    
        const cookie: string = req.body.cookie;

        const userRecipient = await UsersModel.findOne({'cookie': cookie });
        LogMe(1, 'Controller: messages/receiveMessage: cookie checked');    

        if(userRecipient) {

            const messageInQueue = await MessagesModel.findOne({'recipient': userRecipient.username });
            // ToDo: Order messages by date to make sure they are delivered orderly
            // ToDo: Make sure the recipient has received the result of this query before deleting the message

            LogMe(1, 'Controller: messages/receiveMessage: message retrieval from DB done');    

            if(messageInQueue) {

                const deletemessageInQueue = await MessagesModel.deleteOne({'_id': messageInQueue._id });
                LogMe(1, 'Controller: messages/receiveMessage: message deletion done');    

                return {
                    isSuccessful: true,
                    resultMessage: 'Message in queue found.',
                    wasNewMessageFound : true,
                    messageContainer: messageInQueue,
                };
            } else {
                return {
                    isSuccessful: true,
                    wasNewMessageFound : false,
                    resultMessage: 'There are no messages in queue.',
                };
            }
        } else {

            return {
                isSuccessful: false,
                resultMessage: 'Cookie not found on the server.',     
            };
        }

    }


}

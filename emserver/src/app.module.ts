import { Module } from '@nestjs/common';


import { AppService } from './app.service';
import { AppController } from './app.controller';

import { UserController } from './controllers/user.controller';
import { TestController } from './controllers/test.controller';
import { AdministrationController } from './controllers/administration.controller';
import { MessageController } from './controllers/message.controller';

import { ChatGateway } from './gateways/chat.gateway';


@Module({
    imports: [],
    controllers: [AppController, UserController, TestController, AdministrationController, MessageController],
    providers: [AppService, ChatGateway],
})

export class AppModule {}
export class EventsModule {}


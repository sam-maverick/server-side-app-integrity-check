import { Module } from '@nestjs/common';


import { AppService } from './app.service';
import { AppController } from './app.controller';

import { AttestationController } from './controllers/attestation.controller';
import { TestController } from './controllers/test.controller';
import { AdministrationController } from './controllers/administration.controller';





@Module({
    imports: [],
    controllers: [AppController, AttestationController, TestController, AdministrationController],
    providers: [AppService],
})

export class AppModule {}
export class EventsModule {}


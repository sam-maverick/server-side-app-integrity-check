import { Controller, Post, Req } from '@nestjs/common';

import { AppService } from '../app.service';
import UsersModel from '../middleware/database/schemas/user';
import MessagesModel from '../middleware/database/schemas/message';
import { LogMe } from '../serverLibrary';


@Controller('administration')
export class AdministrationController {
    constructor(private readonly appService: AppService) {}

    @Post('/resetFactoryDB')
    async resetDB(@Req() req) {
    
        LogMe(1, 'Controller: administration/resetFactoryDB');    

        const deletedusers = await UsersModel.deleteMany({});
        const deletedmessages = await MessagesModel.deleteMany({});

        return {isSuccessful: true};

    }
  

}

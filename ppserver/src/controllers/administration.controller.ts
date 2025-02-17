import { Controller, Post, Req } from '@nestjs/common';

import { AppService } from '../app.service';
import UsersModel from '../middleware/database/schemas/Device';
import { LogMe } from '../serverLibrary';


@Controller('administration')
export class AdministrationController {
    constructor(private readonly appService: AppService) {}

    @Post('/resetFactoryDB')
    async resetDB(@Req() req) {
    
        LogMe(1, 'Controller: administration/resetFactoryDB');    

        const deletedusers = await UsersModel.deleteMany({});

        return {isSuccessful: true};

    }
  

}

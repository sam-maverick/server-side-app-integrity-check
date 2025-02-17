import { Controller, Post, Req } from '@nestjs/common';

import { AppService } from '../app.service';
import { LogMe } from '../serverLibrary';

@Controller('test')
export class TestController {
    constructor(private readonly appService: AppService) {}


    @Post('/doNothing')
    async doNothing(@Req() req) {

        LogMe(1, 'Controller: test/doNothing');

        return {notice: 'I did nothing'};

    }
  

}

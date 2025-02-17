import { Controller, Get, Post, Req } from '@nestjs/common';

import { AppService } from '../app.service';
import { LogMe } from '../serverLibrary';

// Use this from the server itself to test that it is up & running:
// https://localhost:3020/test/doNothing

@Controller('test')
export class TestController {
    constructor(private readonly appService: AppService) {}


    @Post('/doNothing')
    async doNothingPost(@Req() req) {

        LogMe(1, 'Controller: test/doNothing');

        return {notice: 'I did nothing, I didn\'t do anything, hence contradiction'};

    }

    @Get('/doNothing')
    async doNothingGet(@Req() req) {

        LogMe(1, 'Controller: test/doNothing');

        return {notice: 'I did nothing, I didn\'t do anything, hence contradiction'};

    }
    

}

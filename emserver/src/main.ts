import { NestFactory } from '@nestjs/core';
import * as bodyParser from 'body-parser';


import { AppModule } from './app.module';
import ConnectDB from './middleware/database/index';

import { PARAM_API_PORT } from './parameters';



async function bootstart() {
    await ConnectDB();

    const app = await NestFactory.create(AppModule, { cors: true });
    
    app.use(bodyParser.json({limit: '100mb'}));
    app.use(bodyParser.urlencoded({limit: '100mb', extended: true}));
    app.enableCors();
    
    await app.listen(PARAM_API_PORT);
}

bootstart();


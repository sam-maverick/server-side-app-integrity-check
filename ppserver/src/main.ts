import { NestFactory } from '@nestjs/core';
import * as bodyParser from 'body-parser';
import * as androidintegrityapi from './attestationapi/androidintegrityapi';

import { AppModule } from './app.module';
import ConnectDB from './middleware/database/index';

import { PARAM_API_PORT, PARAM_HTTPS_ENABLED } from './parameters';

import * as fs from 'fs';

async function bootstart() {

    await androidintegrityapi.Initialize();

    if ( ! PARAM_HTTPS_ENABLED) {
        console.log();
        console.log('\x1b[31m%s\x1b[0m', '!!!!!!  WARNING  ----  WARNING  ---- WARNING  !!!!!!');    
        console.log();
        console.log('\x1b[31m%s\x1b[0m', 'PARAM_HTTPS_ENABLED has been set to false.');
        console.log();
    }

    const httpsOptions = (
        PARAM_HTTPS_ENABLED 
        ? 
        {
            key: fs.readFileSync('./secrets/https/srv/srv_priv.key'),
            cert: fs.readFileSync('./secrets/https/srv/srv_cert.cer'),
        }
        :
        {}
    );

    await ConnectDB();

    const server_options = (
        PARAM_HTTPS_ENABLED
        ?
        { 
            cors: true, 
            httpsOptions: httpsOptions,
        }
        :
        { 
            cors: true, 
        }
    );

    const app = await NestFactory.create(AppModule, server_options);
    
    app.use(bodyParser.json({limit: '100mb'}));
    app.use(bodyParser.urlencoded({limit: '100mb', extended: true}));
    app.enableCors();
    
    await app.listen(PARAM_API_PORT);
}

bootstart();


#!/usr/bin/env node

const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const fs = require('fs');

const certPath = '../secrets/https/srv/srv_cert.cer';

const RunCommand = async (command) => {
    const result = await exec(command);
    if (result.stdout.trim() != '')  console.log(result.stdout);
    if (result.stderr.trim() != '')  console.error(result.stderr);
    return result;
}

function trocaHex(c) {
    switch(c) {
        case '0': return('1'); break;
        case '1': return('2'); break;
        case '2': return('3'); break;
        case '3': return('4'); break;
        case '4': return('5'); break;
        case '5': return('6'); break;
        case '6': return('7'); break;
        case '7': return('8'); break;
        case '8': return('9'); break;
        case '9': return('a'); break;
        case 'a': return('b'); break;
        case 'b': return('c'); break;
        case 'c': return('d'); break;
        case 'd': return('e'); break;
        case 'e': return('f'); break;
        case 'f': return('0'); break;
        default:
            console.error('Unexpected hex character: '+c);
            process.exit(1);
    }
}



const Main = async () => {
    // Extract raw signature bytes from certificate
    const cmd = 'openssl x509 -in ' + certPath + ' -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame';
    let resultCmd = await RunCommand(cmd);
    let resultCmdStr = resultCmd.stdout.replace(/\n/g, '');
    let regexSign = /Signature Value:(.+)/;
    let ret = regexSign.exec(resultCmdStr);
    if (ret.length != 2) {
        console.error('Unexpected error when extracting signature. Expected 1 match; obtained: '+ret.length);
        process.exit(1);
    }

    let rawHexStr = ret[1].replace(/ /g, '');
    let rawHexStrPartColon = rawHexStr.substring(0, 18*3);
    let rawHexStrPartColonModified = trocaHex(rawHexStrPartColon.substring(0, 1)) + rawHexStrPartColon.substring(1);

    let fileContents = fs.readFileSync(certPath, 'utf8');

    // Replace signature in header text of the CER file
    let fileContentsVar1 = fileContents.replace(rawHexStrPartColon, rawHexStrPartColonModified);
    //

    //console.log(fileContents);

    let regexBegin1 = /^([\s\S.]+)-----BEGIN CERTIFICATE-----([\s\S.]+)-----END CERTIFICATE-----([\s\S.]+)-----BEGIN CERTIFICATE-----([\s\S.]+)-----END CERTIFICATE-----([\s\S.]+)$/;
    let fileContentsBegin1 = fileContents.match(regexBegin1);

    if (fileContentsBegin1.length != 6) {
        console.error('Unexpected error when extracting BEGIN1. Expected 6 matches; obtained: '+fileContentsBegin1.length);
        process.exit(1);
    }

    let begin1 = fileContentsBegin1[2];

    begin1formatted = begin1.replace(/\n/g, '');
    begin1formattedHex = Buffer.from(begin1formatted, 'base64').toString('hex');


    begin1formattedHexModified = begin1formattedHex.replace(rawHexStrPartColon.replace(/:/g,''), rawHexStrPartColonModified.replace(/:/g,''));

    begin1formattedHexModifiedDeformatted = '\n' + Buffer.from(begin1formattedHexModified, 'hex').toString('base64').
        replace(/(.{64})/g,"$1\n");

    // Replace signature in BASE64 contents (first BEGIN SIGNATURE block) of the CER file
    let fileContentsVar2 = fileContents.replace(begin1, begin1formattedHexModifiedDeformatted);
    //

    // Replace signature in BASE64 contents (first BEGIN SIGNATURE block) of the CER file
    let fileContentsVar3 = fileContentsVar1.replace(begin1, begin1formattedHexModifiedDeformatted);
    //
    
    console.log('Crafted cert:\n\n' + fileContents);

    fs.writeFileSync('./wrong-signature-textHeaderOnly.cer', fileContentsVar1);

    // Having an invalid signature in the BEGIN CERTIFICATE section is what offends Apple
    // The text header section does not offend Apple
    fs.writeFileSync('./wrong-signature-beginCertificateSectionOnly.cer', fileContentsVar2);

    fs.writeFileSync('./wrong-signature-both.cer', fileContentsVar3);
    
   
}


Main();


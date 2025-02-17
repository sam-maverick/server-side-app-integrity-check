const fs = require("fs");
const path = require('path');


function removeAllFilesSync(directory) {
    const files = fs.readdirSync(directory);
    
    for (const file of files) {
        const filePath = path.join(directory, file);
        fs.unlinkSync(filePath);
        console.log('Deleted: '+filePath);
    }
}



// DO THE JOB:

removeAllFilesSync('./bundled_files/json/');

fs.readdirSync('./bundled_files/source/').forEach(file => {
    //Print file name
    console.log('Bundling asset: '+file);

    const contents = fs.readFileSync('./bundled_files/source/'+file, {encoding: 'base64'});

    jsonedcontents = '{"data": "' + contents + '"}';

    fs.writeFileSync('./bundled_files/json/'+file+'.json', jsonedcontents);

    console.log('Done with asset: '+file);
})


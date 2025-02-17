#!/usr/bin/env node
require('shelljs/global');
echo('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ');
echo('BEGIN: UPDATING SYSTEM');
echo('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ');


const replaceInFile = (myfilepath, mypattern, mynewtext) => {
  try {
    echo('replaceOnceInFile started');    
    var fs = require('fs');
    var path = require('path');

    var text = fs.readFileSync(myfilepath, {encoding: 'utf8', flag: 'r'});
   
    //echo('Previous text: '+text);
    text = text.toString().replace(mypattern, mynewtext);
    //echo('Modified text: '+text);

    fs.writeFileSync(myfilepath, text, {encoding: 'utf8', flag: 'w+'});

    echo('replaceOnceInFile done');    

  } catch (err) {
    echo('replaceInFile() error: '+err.message);
  }

}



// Note: Applied workaround: https://github.com/margelo/react-native-quick-crypto/issues/242
// in package.json of project root

// Note: For any submodules that are needed, do install them on the *root* project only.

// Note: For any patches to be applied to submodules, use 'sed' to modify the submodule if patch-package doesn't work. See 'podspecsPath' below as an example.

echo('Patching source code of installed modules from diff files in patches folder');
exec('npx patch-package');

//-//echo('Backing up tsconfig.json');
//-//cp('./node_modules/expo-file-system/tsconfig.json', './node_modules/expo-file-system/tsconfig.json.tmp');

//-//echo('Installing necessary modules within expo-file-system, including the expo-module');
//-//exec('npm install --prefix node_modules/expo-file-system');

//-//echo('Restoring tsconfig.json');
//-//mv('./node_modules/expo-file-system/tsconfig.json.tmp', './node_modules/expo-file-system/tsconfig.json');

echo('Patching podspecsPath undefined');
echo('See https://github.com/expo/expo/pull/20789');

//!!!!sed -r 's/    const podspecPath = podspecs\[0\];/echo -n "    const podspecPath = podspecs[0] ?? '';"/ge' ./node_modules/expo-file-system/node_modules/expo-module-scripts/bin/expo-module-readme > ./node_modules/expo-file-system/node_modules/expo-module-scripts/bin/expo-module-readme.tmp
replaceInFile(
'./node_modules/expo-file-system/node_modules/expo-module-scripts/bin/expo-module-readme', 
/    const podspecPath = podspecs\[0\];/g,
"    const podspecPath = podspecs[0] ?? '';"
);
//sed -r 's/    const podspecPath = podspecs\[0\];/echo -n "    const podspecPath = podspecs[0] ?? '';"/ge' ./node_modules/expo-file-system/node_modules/expo-module-scripts/bin/expo-module-readme > ./node_modules/expo-file-system/node_modules/expo-module-scripts/bin/expo-module-readme.tmp


// Already done by patch-package
//echo "Patching references to stream package in cipher-base and hash-base packages"
//sed -r 's/var Transform = require\(\x27stream\x27\)\.Transform/echo -n "var Transform = require(''readable-stream'').Transform"/ge' ./node_modules/expo-file-system/node_modules/cipher-base/index.js > ./node_modules/expo-file-system/node_modules/cipher-base/index.js.tmp
//mv ./node_modules/expo-file-system/node_modules/cipher-base/index.js.tmp ./node_modules/expo-file-system/node_modules/cipher-base/index.js
//sed -r 's/var Transform = require\(\x27stream\x27\)\.Transform/echo -n "var Transform = require(''readable-stream'').Transform"/ge' ./node_modules/expo-file-system/node_modules/hash-base/index.js > ./node_modules/expo-file-system/node_modules/hash-base/index.js.tmp
//mv ./node_modules/expo-file-system/node_modules/hash-base/index.js.tmp ./node_modules/expo-file-system/node_modules/hash-base/index.js

//-//echo('For some reason, the \'npm install\' command eliminates "**/__stories__/*" from tsconfig.json, which causes issues to patches of tsconfig.json, so we re-include that');

//!!!!sed -r 's/  "exclude": \["\*\*\/__mocks__\/\*", "\*\*\/__tests__\/\*"\]/echo -n "  \\"exclude\\": \[\\"\*\*\/__mocks__\/\*\\", \\"\*\*\/__tests__\/\*\\", \\"\*\*\/__stories__\/\*\\"\]"/ge' ./node_modules/expo-file-system/tsconfig.json > ./node_modules/expo-file-system/tsconfig.json.tmp
//-//replaceInFile(
//-//'./node_modules/expo-file-system/tsconfig.json', 
//-///  "exclude": \["\*\*\/__mocks__\/\*", "\*\*\/__tests__\/\*"\]/g,
//-//"  \"exclude\": \[\"\*\*\/__mocks__\/\*\", \"\*\*\/__tests__\/\*\", \"\*\*\/__stories__\/\*\"\]"
//-//);
//sed -r 's/  "exclude": \["\*\*\/__mocks__\/\*", "\*\*\/__tests__\/\*"\]/echo -n "  \\"exclude\\": \[\\"\*\*\/__mocks__\/\*\\", \\"\*\*\/__tests__\/\*\\", \\"\*\*\/__stories__\/\*\\"\]"/ge' ./node_modules/expo-file-system/tsconfig.json > ./node_modules/expo-file-system/tsconfig.json.tmp


//-//mv('./node_modules/expo-file-system/tsconfig.json.tmp', './node_modules/expo-file-system/tsconfig.json');

//-//echo('Clearing build directory');
//-//rm('-r', './node_modules/expo-file-system/build');

//-//echo('Building JS files to build/ from TS files in src/, without watch option');
//-//echo('Note that expo-file-system comes with dist folder by default, so we need to spread changes from TS to JS');
//-//exec('npm run tsc --prefix node_modules/expo-file-system');

//-//echo('Contents of ./node_modules/expo-file-system/tsconfig.json: ');
//-//cat('./node_modules/expo-file-system/tsconfig.json');

echo('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ');
echo('END: UPDATING SYSTEM');
echo('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ');

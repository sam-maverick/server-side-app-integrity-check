#!/usr/bin/env node
require('shelljs/global');

echo('Updating patch files with the latest changes');
echo('=========================================================================================');
echo('NOTE: Do not interrupt util finished saving patches');
echo('=========================================================================================');
echo('Check: https://github.com/ds300/patch-package#readme');
//rm('-r', './patches/*');
exec('npx patch-package expo-image-multiple-picker --exclude "^dummy\\$" --include "^lib/index\\\\.js\\$"');
exec('npx patch-package react-native-blob-util --exclude "^dummy\\$" --include "^android/src/|^class/"');



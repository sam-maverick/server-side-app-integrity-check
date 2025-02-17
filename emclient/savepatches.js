#!/usr/bin/env node
require('shelljs/global');

echo('Updating patch files with the latest changes');
echo('=========================================================================================');
echo('NOTE: Do not interrupt util finished saving patches');
echo('=========================================================================================');
echo('Check: https://github.com/ds300/patch-package#readme');
echo('We include package.json (by default it is excluded), and we exclude the build dir');
//rm('-r', './patches/*');
exec('npx patch-package react-native-file-provider --exclude "^dummy\\$" --include "^android/build\\\\.gradle\\$|^android/src"');
exec('npx patch-package cipher-base --use-yarn --exclude "^dummy\\$" --include "^index\\\\.js\\$"');
//exec('npx patch-package hash-base --use-yarn --exclude "^dummy\\$" --include "^index\\\\.js\\$"');
exec('npx patch-package png-metadata --exclude "^dummy\\$" --include "^lib/png-metadata\\\\.js\\$"');
exec('npx patch-package react-native-app-link --exclude "^dummy\\$" --include "^index\\\\.js\\$"');
exec('npx patch-package react-native-send-intent --exclude "^dummy\\$" --include "^android/src"');
//exec('npx patch-package react-native-binary-fs --exclude "^dummy\\$" --include "^android/build\\\\.gradle\\$|^android/src|^android/CMakeLists\\\\.txt"');
exec('npx patch-package react-native-binary-file --exclude "^dummy\\$" --include "^android/build\\\\.gradle\\$"');
// OS update patch
exec('npx patch-package expo-file-system --exclude "^dummy\\$" --include "^tsconfig\\\\.json\\$|^package\\\\.json\\$|^src/"');
exec('npx patch-package react-native-lightbox-v2 --exclude "^dummy\\$" --include "^dist/"');
exec('npx patch-package piexifjs --exclude "^dummy\\$" --include "^piexif\\.js$"');
//exec('npx patch-package expo-media-library --exclude "^dummy\\$" --include "^android/build\\\\.gradle\\$"');
//exec('npx patch-package react-native-quick-crypto --exclude "^dummy\\$" --include "^android/build\\\\.gradle\\$"');

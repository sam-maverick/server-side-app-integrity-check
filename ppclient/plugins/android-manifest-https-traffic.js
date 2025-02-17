const { createRunOncePlugin, withAndroidManifest } = require('@expo/config-plugins');

const withAndroidManifestHttpConfigurations = config => {
  return withAndroidManifest(config, config => {
    const androidManifest = config.modResults.manifest;
    const mainApplication = androidManifest.application[0];

    console.warn('withAndroidManifestHttpConfigurations started');

    androidManifest.$ = {
      ...androidManifest.$,
      'xmlns:tools': 'http://schemas.android.com/tools',
    };
    
    mainApplication.$['android:networkSecurityConfig'] = '@xml/network_security_config';

    try {
      const fs = require('fs');
      const path = require('path');
  
      //const pathbase = path.parse(__dirname).dir+'/';
      const xmldir = 'android/app/src/main/res/xml/';
      fs.mkdirSync(xmldir, { recursive: true });
    
      fs.copyFileSync(
        'plugins/android-manifest-https-traffic__files/network_security_config.xml', 
        xmldir+'network_security_config.xml',
      );    
    } catch (err) {
      console.warn('Error when copying network_security_config.xml: '+err.message);
      process.exit(1);
    }

    try {
      const fs = require('fs');
      const path = require('path');
  
      //const pathbase = path.parse(__dirname).dir+'/';
      const rawdir = 'android/app/src/main/res/raw/';
      fs.mkdirSync(rawdir, { recursive: true });
    
      fs.copyFileSync(
        'assets/custom/ca_cert.cer', 
        rawdir+'my_ca',  // Do not use file extension for the file name
      );    
    } catch (err) {
      console.warn('Error when copying ca_cert.cer: '+err.message);
      process.exit(1);
    }

    return config;
  });
};

module.exports = createRunOncePlugin(
  withAndroidManifestHttpConfigurations,
  'withAndroidManifestHttpConfigurations',
  '1.0.0'
);

// https://stackoverflow.com/questions/72171458/how-to-add-values-to-app-json-for-android-in-expo-managed-workflow
// https://stackoverflow.com/questions/75013370/create-a-expo-config-plugin-file-to-modify-android-manifest

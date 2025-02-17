const { createRunOncePlugin, withAndroidManifest } = require('@expo/config-plugins');

const withAndroidManifestRequestLegacyExternalStorageConfigurations = config => {
  return withAndroidManifest(config, config => {
    const androidManifest = config.modResults.manifest;
    const mainApplication = androidManifest.application[0];

    console.warn('withAndroidManifestRequestLegacyExternalStorageConfigurations started');

    androidManifest.$ = {
      ...androidManifest.$,
      'xmlns:tools': 'http://schemas.android.com/tools',
    };
    
    mainApplication.$['android:requestLegacyExternalStorage'] = 'true';

    return config;
  });
};

module.exports = createRunOncePlugin(
  withAndroidManifestRequestLegacyExternalStorageConfigurations,
  'withAndroidManifestRequestLegacyExternalStorageConfigurations',
  '1.0.0'
);

// https://stackoverflow.com/questions/72171458/how-to-add-values-to-app-json-for-android-in-expo-managed-workflow
// https://stackoverflow.com/questions/75013370/create-a-expo-config-plugin-file-to-modify-android-manifest

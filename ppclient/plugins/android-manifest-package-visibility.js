//https://developer.android.com/training/package-visibility/declaring
const { XML, createRunOncePlugin, withAndroidManifest } = require('@expo/config-plugins');
const { mkdirSync } = require("fs");

const withAndroidManifestPackageVisibilityConfigurations = config => {
  return withAndroidManifest(config, async (config) => {

    // modify manifest

    console.warn('withAndroidManifestPackageVisibilityConfigurations started');

    const manifest = config.modResults.manifest;

    manifest.$ = {
      ...manifest.$,
      'xmlns:tools': 'http://schemas.android.com/tools',
    };

    // Check if there are any application tags
    if (!Array.isArray(manifest['application'])) {
      console.warn('withAndroidManifestPackageVisibilityConfigurations: No application array in manifest?');
      return manifest;
    }
  
    let queries = manifest['queries'].find(
        (item) => 1===1
    );
    if (!queries) {
      console.warn('withAndroidManifestFileProviderConfigurations: No queries tag?');
      return manifest;
    }
    
    const packagetagcontents = {
        $: {
            'android:name': 'pt.lasige.safex.enhmessageme',
        }
    }

    const providertagcontents = {
        $: {
            'android:authorities': 'pt.lasige.safex.enhmessageme.MyFileProvider',
        }
    }

    /*
    
    NOTE

    Because of this:
    https://developer.android.com/training/package-visibility/automatic
    `Any app that has a content provider that your app has been granted URI permissions to access.`,

    it should not necessary to add the <application><queries><provider> or <application><queries><package> tag.
    However, we get a "ActivityThread: Failed to find provider info for pt.lasige.safex.enhmessageme" error

    */

    //queries['package'] = packagetagcontents;
    //queries['provider'] = providertagcontents;


    // return result

    return config;
  });
};

module.exports = createRunOncePlugin(
  withAndroidManifestPackageVisibilityConfigurations,
  'withAndroidManifestPackageVisibilityConfigurations',
  '1.0.0'
);


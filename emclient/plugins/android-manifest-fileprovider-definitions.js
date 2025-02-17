
const { XML, createRunOncePlugin, withAndroidManifest } = require('@expo/config-plugins');
const { mkdirSync } = require("fs");

const withAndroidManifestFileProviderConfigurations = config => {
  return withAndroidManifest(config, async (config) => {

    // modify manifest
    
    console.warn('withAndroidManifestFileProviderConfigurations started');

    const manifest = config.modResults.manifest;

    manifest.$ = {
      ...manifest.$,
      'xmlns:tools': 'http://schemas.android.com/tools',
    };

    // Check if there are any application tags
    if (!Array.isArray(manifest['application'])) {
      console.warn('withAndroidManifestFileProviderConfigurations: No application array in manifest?');
      return manifest;
    }
  
    // Find the "application" called ".MainApplication"
    let application = manifest['application'].find(
      (item) => item.$['android:name'] === '.MainApplication'
    );
    if (!application) {
      console.warn('withAndroidManifestFileProviderConfigurations: No .MainApplication?');
      return manifest;
    }

    const providertagcontents = {
        $: {
            'android:name': 'com.artirigo.fileprovider.MyFileProvider',
            'android:authorities': 'pt.lasige.safex.enhmessageme.MyFileProvider',
            'android:grantUriPermissions': 'true',
            'android:permission': 'pt.lasige.safex.permission.PRIVACY_PROVIDER',  // The PP client app will need this permission to access the content provided by MyFileProvider. The calling code from the messaging app (system update) will also need to set grantUriPermission()
            // NOTE: In Android 11 we have observed that granting the permission through the GUI is not necessary but grantUriPermission() is necessary and having the permission in the manifest is necessary.
            'android:exported': 'true',  // Setting this to 'true' causes a 'Provider must not be exported' SecurityException when using android.content.FileProvider
            /**
            * According to https://developer.android.com/guide/topics/manifest/provider-element.html#exported, 
            * you can set android:exported=false and still share files with the ContentProvider, but then you need to configure and use custom permissions:
            * https://developer.android.com/guide/topics/manifest/provider-element#prmsn
            * As a workaround, we have created our own MyFileProvider class extending ContentProvider, which allows the exported=true flag.
            */
        },
        'meta-data': {
            $: {
                'android:name': 'android.support.FILE_PROVIDER_PATHS',
                'android:resource': '@xml/filepaths',
            }
        }
    };

    application['provider'] = providertagcontents;
    
    const custompermissiontagcontents = {
        $: {
            //'android:description': "Privacy Provider client apps will need this permission to operate. This gives the app access to private pictures.",
            'android:name': "pt.lasige.safex.permission.PRIVACY_PROVIDER",
            'android:label': "Privacy Provider",
            'android:protectionLevel': "dangerous",
        }
    };
    
    manifest['permission'] = custompermissiontagcontents;


    // create file_paths.xml
    const dir = "android/app/src/main/res/xml";

    const filepathscontents = {
      'paths': {
        $: {
          'xmlns:android': 'http://schemas.android.com/apk/res/android',
        },
        'files-path': {
          $: {
            'name': 'ppimg',
            'path': 'ppSharedImages/',
          }
        }
      }
    }

    mkdirSync(dir, { recursive: true });
    await XML.writeXMLAsync({ path: `${dir}/filepaths.xml`, xml: filepathscontents });


    // return result

    return config;
  });
};

module.exports = createRunOncePlugin(
  withAndroidManifestFileProviderConfigurations,
  'withAndroidManifestFileProviderConfigurations',
  '1.0.0'
);


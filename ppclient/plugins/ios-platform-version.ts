const { createRunOncePlugin, withInfoPlist } = require('expo/config-plugins');

// https://forums.developer.apple.com/forums/thread/656616


const withInfoPlistPlatformVersion = (config, id) => {
  return withInfoPlist(config, async(config) => {

    console.warn('withInfoPlistPlatformVersion started');

    const fs = require('fs');

    // Modifications to the Podfile

    let PodfileOriginalContents = fs.readFileSync('ios/Podfile', {encoding: 'utf8'});

    if ( ! PodfileOriginalContents.includes('config.build_settings[\'IPHONEOS_DEPLOYMENT_TARGET\'] = ')) {
      let PodfileModifiedContents = PodfileOriginalContents.replace(
        '  post_install do |installer|', 
        '  post_install do |installer|\n\n\
    installer.pods_project.targets.each do |target|\n\
      target.build_configurations.each do |config|\n\
        config.build_settings[\'IPHONEOS_DEPLOYMENT_TARGET\'] = \'12.0\'\n\
      end\n\
    end\n'
      );

      if ( ! PodfileModifiedContents.includes('config.build_settings[\'IPHONEOS_DEPLOYMENT_TARGET\'] = ')) {
        console.error('Error: We expected the patch to be applied or to be already present.');
        process.exit(1);
      }
  
      fs.writeFileSync('ios/Podfile', PodfileModifiedContents, {encoding: 'utf8'});
  
      //console.warn('PodfileModifiedContents:');
      //console.warn(PodfileModifiedContents);
  
    }


    return config;
  });
};

module.exports = createRunOncePlugin(
  withInfoPlistPlatformVersion,
  'withInfoPlistPlatformVersion',
  '1.0.0'
);


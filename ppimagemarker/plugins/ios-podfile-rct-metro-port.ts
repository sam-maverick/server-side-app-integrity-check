const { createRunOncePlugin, withInfoPlist } = require('expo/config-plugins');

// https://github.com/facebook/react-native/issues/30708


const withInfoPlistRctMetroPort = (config, id) => {
  return withInfoPlist(config, async(config) => {

    console.warn('withInfoPlistRctMetroPort started');
    
    const fs = require('fs');

    // Modifications to the Podfile

    let PodfileOriginalContents = fs.readFileSync('ios/Podfile', {encoding: 'utf8'});

    if ( ! PodfileOriginalContents.includes('config.build_settings["DEVELOPMENT_TEAM"]')) {
      let PodfileModifiedContents = PodfileOriginalContents.replace(
        '  post_install do |installer|', '\
  post_install do |installer|\n\n\
\n\
    # Port fix\n\
    installer.pods_project.build_configurations.each do |config|\n\
      config.build_settings[\'GCC_PREPROCESSOR_DEFINITIONS\'].insert(0, "RCT_METRO_PORT=${RCT_METRO_PORT}")\n\
    end\n'
      );
  
      if ( ! PodfileModifiedContents.includes('config.build_settings[\'GCC_PREPROCESSOR_DEFINITIONS\'].')) {
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
  withInfoPlistRctMetroPort,
  'withInfoPlistRctMetroPort',
  '1.0.0'
);


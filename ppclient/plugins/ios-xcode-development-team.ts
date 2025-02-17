const { createRunOncePlugin, withInfoPlist } = require('expo/config-plugins');

// https://forums.developer.apple.com/forums/thread/656616


const withInfoPlistXcodeDevelopmentTeam = (config, id) => {
  return withInfoPlist(config, async(config) => {

    console.warn('withInfoPlistXcodeDevelopmentTeam started');

    const fs = require('fs');

    // Modifications to the Podfile

    let PodfileOriginalContents = fs.readFileSync('ios/ppclient.xcodeproj/project.pbxproj', {encoding: 'utf8'});

    if ( ! PodfileOriginalContents.includes('DEVELOPMENT_TEAM')) {
      let PodfileModifiedContents = PodfileOriginalContents.replace(
        'ENABLE_BITCODE = ', 
        'DEVELOPMENT_TEAM = L549K3FQ5X;\n\
				ENABLE_BITCODE = '
      );
  
      if ( ! PodfileModifiedContents.includes('DEVELOPMENT_TEAM = ')) {
        console.error('Error: We expected the patch to be applied or to be already present.');
        process.exit(1);
      }
  
      fs.writeFileSync('ios/ppclient.xcodeproj/project.pbxproj', PodfileModifiedContents, {encoding: 'utf8'});
  
      //console.warn('PodfileModifiedContents:');
      //console.warn(PodfileModifiedContents);
  
    }


    return config;
  });
};

module.exports = createRunOncePlugin(
  withInfoPlistXcodeDevelopmentTeam,
  'withInfoPlistXcodeDevelopmentTeam',
  '1.0.0'
);


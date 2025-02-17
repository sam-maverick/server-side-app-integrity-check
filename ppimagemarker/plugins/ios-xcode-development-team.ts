const { createRunOncePlugin, withInfoPlist } = require('expo/config-plugins');

// https://forums.developer.apple.com/forums/thread/656616


const withInfoPlistXcodeDevelopmentTeam = (config, id) => {
  return withInfoPlist(config, async(config) => {

    const fs = require('fs');

    // Modifications to the Podfile

    let PodfileOriginalContents = fs.readFileSync('ios/ppimagemarker.xcodeproj/project.pbxproj', {encoding: 'utf8'});

    if ( ! PodfileOriginalContents.includes('DEVELOPMENT_TEAM')) {
      let PodfileModifiedContents = PodfileOriginalContents.replace(
        'ENABLE_BITCODE = ', 
        'DEVELOPMENT_TEAM = L549K3FQ5X;\n\
				ENABLE_BITCODE = '
      );
  
      fs.writeFileSync('ios/ppimagemarker.xcodeproj/project.pbxproj', PodfileModifiedContents, {encoding: 'utf8'});
  
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


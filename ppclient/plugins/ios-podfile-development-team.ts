const { createRunOncePlugin, withInfoPlist } = require('expo/config-plugins');

// https://forums.developer.apple.com/forums/thread/656616


const withInfoPlistDevelopmentTeam = (config, id) => {
  return withInfoPlist(config, async(config) => {

    console.warn('withInfoPlistDevelopmentTeam started');

    // 

    /**
     * Apparently, this is not enough. It keeps throwing an error when the EAS build command
     * calls xcode to compile. It complains about missing DEVELOPMENT TEAM, and prompts to
     * configure it with the Xcode app on MAC under the Signing & Capabilities tab.
     * 
     * Setting an environment variable doesn't help.
     * 
     * So we have proceeded with manual modification of the ppclient.xcodeproj, and then
     * we have diff'ed the differences. Then we have created the ios-xcode-development-team.ts
     * plugin to automate the process. Apparently, we need to modify both the Podfile and the 
     * ppclient.xcodeproj/project.pbxproj file
     */


    //

    
    const fs = require('fs');

    // Modifications to the Podfile

    let PodfileOriginalContents = fs.readFileSync('ios/Podfile', {encoding: 'utf8'});

    if ( ! PodfileOriginalContents.includes('config.build_settings["DEVELOPMENT_TEAM"]')) {
      let PodfileModifiedContents = PodfileOriginalContents.replace(
        '  post_install do |installer|', 
        '  post_install do |installer|\n\n\
    installer.generated_projects.each do |project|\n\
      project.targets.each do |target|\n\
        target.build_configurations.each do |config|\n\
          config.build_settings["DEVELOPMENT_TEAM"] = "L549K3FQ5X"\n\
        end\n\
      end\n\
    end\n'
      );
  
      if ( ! PodfileModifiedContents.includes('config.build_settings["DEVELOPMENT_TEAM"] = ')) {
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
  withInfoPlistDevelopmentTeam,
  'withInfoPlistDevelopmentTeam',
  '1.0.0'
);


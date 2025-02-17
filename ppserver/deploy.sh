echo "Updating server-side-app-integrity-check module to the latest version"
npm update server-side-app-integrity-check
RESULT=$?
if [ $RESULT != 0 ]; then
    echo "Aborting on $RESULT, command failed:"
    echo "npm update server-side-app-integrity-check ..."
    exit $RESULT
fi

rm -r ./dist

npm start --reset-cache

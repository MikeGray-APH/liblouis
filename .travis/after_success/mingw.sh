if [ "$TRAVIS_PULL_REQUEST" != "false" -o "$TRAVIS_BRANCH" != "master" ]; then
    echo "[mingw] Not publishing. Is pull request or non-master branch."
    exit 0
fi

echo "[mingw] Zipping up build..."

INSTALL_DIR=out-mingw32-install
COMMIT=$( git rev-parse --short=7 HEAD )
ZIP=liblouis-win32-$COMMIT.zip

make install && \
cd $INSTALL_DIR && \
zip -r $ZIP * &&  \
cd .. &&  \
mv $INSTALL_DIR/$ZIP .

if [ $? != 0 ]; then
    echo "[mingw] Failed to zip up build"
    exit 1
fi

RELEASE_ID=8031256
GITHUB_USER="bertfrees"

echo "[mingw] Uploading builds to Github release..."
echo "[mingw] First deleting previous build"

ASSET_URL=$(
    curl "https://api.github.com/repos/liblouis/liblouis/releases/$RELEASE_ID/assets" 2>/dev/null \
    | jq -r '.[] | select(.name | match("^liblouis-win32-.+\\.zip$")) | .url'
)

if ! curl -u "$GITHUB_USER:$GITHUB_TOKEN" -X DELETE "$ASSET_URL" \
     >/dev/null 2>/dev/null \
    | jq -e '.url'
then
    echo "[mingw] Failed to delete asset"
    exit 1
fi

if ! curl -u "$GITHUB_USER:$GITHUB_TOKEN" \
     -H "Content-type: application/zip" \
     -X POST \
     "https://uploads.github.com/repos/liblouis/liblouis/releases/$RELEASE_ID/assets?name=$ZIP" \
     --data-binary @$ZIP \
     >/dev/null 2>/dev/null \
    | jq -e '.url'
then
    echo "[mingw] Failed to upload asset"
    exit 1
fi

echo "[mingw] Editing release description..."

DESCRIPTION="Latest build: $COMMIT"
if ! curl -u "$GITHUB_USER:$GITHUB_TOKEN" \
     -H "Accept: application/json" \
     -H "Content-type: application/json" \
     -X PATCH \
     "https://api.github.com/repos/liblouis/liblouis/releases/$RELEASE_ID" \
     -d "{\"tag_name\": \"snapshot\", \
          \"body\":     \"$DESCRIPTION\"}" \
      >/dev/null 2>/dev/null \
    | jq -e '.url'
then
    echo "[mingw] Failed to edit release description"
    exit 1
fi

import fs from "fs";
import followRedirects from "follow-redirects";
import dotenv from "dotenv";

dotenv.config();

// Match the Rust client's default so an unset CDN_UPLOAD_DIR mirrors into
// ./upload_cdn instead of the literal string "undefined/maven/...".
const CDN_UPLOAD_DIR = process.env.CDN_UPLOAD_DIR || "./upload_cdn";

const requiresMirroring = (_url) => {
  const url = new URL(_url);
  const domain = url.hostname;

  return domain === "build.lwjgl.org" || domain === "github.com";
};

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(dest.split("/").slice(0, -1).join("/"), { recursive: true });
    console.log(`Downloading ${url} to ${dest}`);

    const file = fs.createWriteStream(dest);

    // createWriteStream has already truncated `dest`, so on any failure we must
    // close and remove it — otherwise a non-200 body (or a partial write) is
    // left in place as a corrupt jar, later republished to the CDN at the same
    // stable /maven URL. fs.unlink needs a callback or it throws on modern Node.
    const fail = (err) => {
      file.close(() => {
        fs.unlink(dest, () => reject(err));
      });
    };

    followRedirects.https
      .get(url, function (response) {
        if (response.statusCode !== 200) {
          console.log(`Error ${response.statusCode} downloading ${url}`);
          response.resume(); // drain so the socket frees up
          fail(new Error(`Error ${response.statusCode} downloading ${url}`));
          return;
        }

        response.pipe(file);
        file.on("finish", function () {
          file.close(() => resolve(true));
        });
        file.on("error", fail);
      })
      .on("error", fail);
  });
}

function intoPath(
  groupId,
  artifactId,
  version,
  identifier,
  additional,
  extension
) {
  let pathParts = groupId.split(".");
  pathParts.push(artifactId);
  pathParts.push(version);

  let versionStr = `-${version}`;

  let identifierStr = identifier ? `-${identifier}` : "";

  let additionalStr = additional ? `-${additional}` : "";

  pathParts.push(
    `${artifactId}${versionStr}${identifierStr}${additionalStr}.${extension}`
  );

  return pathParts.join("/");
}

function generate_lib_path(maven_coordinate, additional_final) {
  const [group, artifact, version, identifier] = maven_coordinate.split(":");

  return intoPath(
    group,
    artifact,
    version,
    identifier,
    additional_final,
    "jar"
  );
}

const patches = JSON.parse(fs.readFileSync("library-patches.json"));

async function main() {
  for (const patch of patches) {
    let baseMatch = patch.match[0];
    let fallbackName = patch.match[0];
    if (patch.additionalLibraries) {
      for (const lib of patch.additionalLibraries) {
        if (lib.downloads.artifact) {
          let libPath = generate_lib_path(lib.name || fallbackName);
          lib.downloads.artifact.path = libPath;

          if (requiresMirroring(lib.downloads.artifact.url)) {
            await downloadFile(
              lib.downloads.artifact.url,
              `${CDN_UPLOAD_DIR}/maven/${libPath}`
            );

            lib.downloads.artifact.url = "${BASE_URL}" + `/maven/${libPath}`;
          }
        }
        if (lib.downloads.classifiers) {
          for (const classifier in lib.downloads.classifiers) {
            let libPath = generate_lib_path(
              lib.name || fallbackName,
              classifier
            );
            lib.downloads.classifiers[classifier].path = libPath;

            if (requiresMirroring(lib.downloads.classifiers[classifier].url)) {
              await downloadFile(
                lib.downloads.classifiers[classifier].url,
                `${CDN_UPLOAD_DIR}/maven/${libPath}`
              );

              lib.downloads.classifiers[classifier].url =
                "${BASE_URL}" + `/maven/${libPath}`;
            }
          }
        }
      }
    }
    if (patch.override && patch.override.downloads) {
      let lib = patch.override;
      if (lib.downloads.artifact) {
        let libPath = generate_lib_path(lib.name || fallbackName);
        lib.downloads.artifact.path = libPath;

        if (requiresMirroring(lib.downloads.artifact.url)) {
          await downloadFile(
            lib.downloads.artifact.url,
            `${CDN_UPLOAD_DIR}/maven/${libPath}`
          );

          lib.downloads.artifact.url = "${BASE_URL}" + `/maven/${libPath}`;
        }
      }
      if (lib.downloads.classifiers) {
        for (const classifier in lib.downloads.classifiers) {
          let libPath = generate_lib_path(lib.name || fallbackName, classifier);
          lib.downloads.classifiers[classifier].path = libPath;

          if (requiresMirroring(lib.downloads.classifiers[classifier].url)) {
            await downloadFile(
              lib.downloads.classifiers[classifier].url,
              `${CDN_UPLOAD_DIR}/maven/${libPath}`
            );

            lib.downloads.classifiers[classifier].url =
              "${BASE_URL}" + `/maven/${libPath}`;
          }
        }
      }
    }
  }

  fs.writeFileSync(
    "daedalus_client/patched-library-patches.json",
    JSON.stringify(patches, null, 2)
  );
}

main().then(() => console.log("Done"));

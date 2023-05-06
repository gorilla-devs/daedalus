const fs = require("fs");
const path = require("path");

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

for (patch of patches) {
  let baseMatch = patch.match[0];
  let fallbackName = patch.match[0];
  if (patch.additionalLibraries) {
    for (lib of patch.additionalLibraries) {
      if (lib.downloads.artifact) {
        let libPath = generate_lib_path(lib.name || fallbackName);
        lib.downloads.artifact.path = libPath;
      }
      if (lib.downloads.classifiers) {
        for (_classifier in lib.downloads.classifiers) {
          let classifier = "natives-" + _classifier.split("-")[1];

          let libPath = generate_lib_path(lib.name || fallbackName, classifier);
          lib.downloads.classifiers[_classifier].path = libPath;
        }
      }
    }
  }
  if (patch.override && patch.override.downloads) {
    let lib = patch.override;
    if (lib.downloads.artifact) {
      let libPath = generate_lib_path(lib.name || fallbackName);
      lib.downloads.artifact.path = libPath;
    }
    if (lib.downloads.classifiers) {
      for (_classifier in lib.downloads.classifiers) {
        let classifier = "natives-" + _classifier.split("-")[1];

        let libPath = generate_lib_path(lib.name || fallbackName, classifier);
        lib.downloads.classifiers[_classifier].path = libPath;
      }
    }
  }
}

fs.writeFileSync("library-patches-out.json", JSON.stringify(patches, null, 2));

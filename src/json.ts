import * as fs from "fs";
import * as path from "path";

import { ImageJson } from "./types";

export const generateJson = async (buildDir: string, repoUrl: string, images: string[]) => {
  const withBase = (branch: string, dir: string, name: string, ext: string) => {
    return `${repoUrl}/raw/${branch}/${dir}/${encodeURIComponent(name)}.${ext}`;
  };

  const imageJson: ImageJson[] = images.map((image) => {
    const map = path.basename(path.dirname(image));
    const course = path.parse(image).name;

    return {
      name: `${map} Course ${course}`,
      src: withBase("master", `images/${map}`, course, "jpg"),
      full: withBase("public", `full/${map}`, course, "jpg"),
      medium: withBase("public", `medium/${map}`, course, "jpg"),
      thumb: withBase("public", `thumbnail/${map}`, course, "jpg"),
      webp: withBase("public", `webp/full/${map}`, course, "webp"),
      webp_medium: withBase("public", `webp/medium/${map}`, course, "webp"),
      webp_thumb: withBase("public", `webp/thumbnail/${map}`, course, "webp"),
    };
  });

  const prettyJson = JSON.stringify(imageJson, null, 2);
  const minifiedJson = JSON.stringify(imageJson, null, 0);

  const prettyJsonPath = path.join(buildDir, "maps.json");
  const minifiedJsonPath = path.join(buildDir, "maps.min.json");

  // Append is fine here, the build dir is fresh everytime
  return Promise.all([
    fs.promises.appendFile(prettyJsonPath, prettyJson),
    fs.promises.appendFile(minifiedJsonPath, minifiedJson),
  ]);
};

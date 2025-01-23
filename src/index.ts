import * as path from "path";
import * as core from "@actions/core";
import * as github from "@actions/github";

import { generateJson } from "./json";
import { generateMarkdown } from "./markdown";

import { ImageService } from "./images";

import { validEvents, validExtensions, removalStatuses, generateStatuses } from "./constants";

import { FileInfo } from "./types";
import { getFilesInDir, ensureDir, listEntries, timePromise } from "./utils";

export const run = async () => {
  const srcDir = "images";
  const buildDir = "public";

  // const token = core.getInput("token");

  // const srcDir = core.getInput("src_dir");
  // const buildDir = core.getInput("build_dir");

  // const context = github.context;
  // const repoUrl = context.payload.repository?.html_url;

  // const event = context.eventName;
  // if (!validEvents.includes(event)) {
  //   return core.setFailed(`Invalid event ${event}`);
  // }

  // if (!repoUrl) {
  //   return core.setFailed("Failed to retrieve repository url");
  // }

  // if (context.ref !== "refs/heads/master") {
  //   return core.setFailed("This action can only be invoked on master");
  // }

  // core.info(`Received event ${event}`);

  const toRemove: FileInfo[] = [{ map: "bkz_bonus", name: "4", filepath: "images/bkz_bonus/4.jpg" }];
  const toGenerate: FileInfo[] = [];

  // const allImages = await getFilesInDir("images", validExtensions);

  // if (event === "push") {
  //   const octokit = github.getOctokit(token);

  //   const response = await octokit.rest.repos.compareCommits({
  //     ...context.repo,
  //     head: context.payload.after,
  //     base: context.payload.before,
  //   });

  //   const files = response.data.files;
  //   if (!files) {
  //     return core.setFailed("Could not get diff");
  //   }

  //   const imageFiles = files.filter((f) => {
  //     const parsed = path.parse(f.filename);

  //     const goodExt = validExtensions.includes(parsed.ext);
  //     const goodFilename = /^\d+$/.test(parsed.name);
  //     const goodDir = path.dirname(path.resolve(parsed.dir)) === path.resolve(srcDir);

  //     return goodExt && goodFilename && goodDir;
  //   });

  //   console.log("changed files", imageFiles);

  //   const removed = imageFiles.filter((f) => removalStatuses.includes(f.status));
  //   const modified = imageFiles.filter((f) => generateStatuses.includes(f.status));

  //   toRemove.push(
  //     ...removed.map((f) => {
  //       const map = path.basename(path.dirname(f.filename));
  //       return { map, name: path.parse(f.filename).name, filepath: f.filename };
  //     })
  //   );
  //   toGenerate.push(
  //     ...modified.map((f) => {
  //       const map = path.basename(path.dirname(f.filename));
  //       return { map, name: path.parse(f.filename).name, filepath: f.filename };
  //     })
  //   );
  // }

  listEntries(
    "To be removed images",
    toRemove.map((f) => `${f.map} - ${f.name}`)
  );
  listEntries(
    "To be generated images",
    toGenerate.map((f) => `${f.map} - ${f.name}`)
  );

  const imageService = new ImageService(buildDir);

  const removeTasks = toRemove.map((image) => {
    return imageService.removeImage(image);
  });

  const generateTasks = toGenerate.map((image) => {
    return imageService.generateImage(image);
  });

  await ensureDir(buildDir);

  await timePromise("Remove images", Promise.all(removeTasks));
  await timePromise("Generate images", Promise.all(generateTasks));

  // await timePromise("Generate JSON", generateJson(buildDir, repoUrl, allImages));
  // await timePromise("Generate README", generateMarkdown(buildDir, allImages));

  core.notice(`Removed ${removeTasks.length} images`);
  core.notice(`Generated ${generateTasks.length} images`);
};

run().catch((err) => {
  const errMsg = err?.message ?? "Unknown error";

  console.error(errMsg);
  core.setFailed(`Failed building images: ${errMsg}`);
});

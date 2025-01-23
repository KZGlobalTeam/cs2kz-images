import gm from "gm";
import * as fs from "fs";
import * as path from "path";

import { ensureDir } from "./utils";
import { ImageFormat, ImageVariant, ImageDimensions, FileInfo } from "./types";

const variants: Record<ImageVariant, ImageDimensions> = {
  full: [1920, 1080],
  medium: [512, undefined],
  thumbnail: [200, undefined],
};

const variantDirs: Record<ImageFormat, Record<ImageVariant, string>> = {
  jpg: {
    full: "full",
    medium: "medium",
    thumbnail: "thumbnail",
  },
  webp: {
    full: "webp/full",
    medium: "webp/medium",
    thumbnail: "webp/thumbnail",
  },
};

export class ImageService {
  private readonly buildDir: string;

  constructor(buildDir: string) {
    this.buildDir = buildDir;
  }

  resizeImage(image: string, destPath: string, [w, h]: ImageDimensions) {
    console.log("dest path", destPath);
    return new Promise((resolve, reject) => {
      gm(image)
        .resize(w, h, "!")
        .noProfile()
        .write(destPath, (err) => {
          if (err) return reject(err);
          return resolve(destPath);
        });
    });
  }

  removeImage(srcImage: FileInfo) {
    return Promise.all([
      this.removeImageFormat(srcImage, ImageFormat.JPG),
      this.removeImageFormat(srcImage, ImageFormat.WEBP),
    ]);
  }

  removeImageFormat(srcImage: FileInfo, format: ImageFormat) {
    return Promise.all([
      this.removeImageVariant(srcImage, format, ImageVariant.Full),
      this.removeImageVariant(srcImage, format, ImageVariant.Medium),
      this.removeImageVariant(srcImage, format, ImageVariant.Thumbnail),
    ]);
  }

  removeImageVariant(srcImage: FileInfo, format: ImageFormat, variant: ImageVariant) {
    const destDir = path.join(this.buildDir, variantDirs[format][variant], srcImage.map);

    const destImage = path.join(destDir, `${srcImage.name}.${format}`);

    console.log("removing path", path.resolve(destImage));

    return fs.promises.rm(path.resolve(destImage), { force: true });
  }

  generateImage(srcImage: FileInfo) {
    return Promise.all([
      this.generateImageFormat(srcImage, ImageFormat.JPG),
      this.generateImageFormat(srcImage, ImageFormat.WEBP),
    ]);
  }

  generateImageFormat(srcImage: FileInfo, format: ImageFormat) {
    return Promise.all([
      this.generateImageVariant(srcImage, format, ImageVariant.Full),
      this.generateImageVariant(srcImage, format, ImageVariant.Medium),
      this.generateImageVariant(srcImage, format, ImageVariant.Thumbnail),
    ]);
  }

  async generateImageVariant(srcImage: FileInfo, format: ImageFormat, variant: ImageVariant) {
    const destDir = path.join(this.buildDir, variantDirs[format][variant], srcImage.map);

    await ensureDir(destDir);

    const destImage = path.join(destDir, `${srcImage.name}.${format}`);

    const dimensions = variants[variant];

    return this.resizeImage(path.resolve(srcImage.filepath), path.resolve(destImage), dimensions);
  }
}

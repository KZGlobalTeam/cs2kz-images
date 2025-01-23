import * as fs from "fs";
import * as path from "path";

export const generateMarkdown = async (buildDir: string, images: string[]) => {
  const lines = [
    "| Map | Course | Thumbnail | Full | Medium | Thumb | webp Full | webp Medium | webp Thumb |",
    "|-----|--------|-----------|------|--------|-------|-----------|-------------|------------|",
  ];

  images.forEach((image) => {
    const map = path.basename(path.dirname(image));
    const course = path.parse(image).name;

    const line = [
      `|${map}`,
      `|${course}`,
      `|![${course}](webp/thumbnail/${map}/${course}.webp?raw=true)`,
      `|[image](full/${map}/${course}.jpg?raw=true)`,
      `|[medium](medium/${map}/${course}.jpg?raw=true)`,
      `|[thumbnail](thumbnail/${map}/${course}.jpg?raw=true)`,
      `|[webp](webp/full/${map}/${course}.webp?raw=true)`,
      `|[medium](webp/medium/${map}/${course}.webp?raw=true)`,
      `|[thumbnail](webp/thumbnail/${map}/${course}.webp?raw=true)|`,
    ];

    lines.push(line.join(""));
  });

  const filePath = path.join(buildDir, "README.md");
  return fs.promises.appendFile(filePath, lines.join("\n"));
};

# CS2 KZ Map Images

This repository is based on [map-images](https://github.com/KZGlobalTeam/map-images) and has been modified to suit specific requirements.

Images for global KZ maps available in the following:
- Full (1920x1080) - JPG/WEBP
- Medium (512x288) - JPG/WEBP
- Thumbnail (200x113) - JPG/WEBP

Images in the [source directory](./images) are used to build the variants, high-quality images are preferred.

## Usage

Generated images are in the [public](https://github.com/KZGlobalTeam/cs2kz-images/tree/public) branch.  

The following are available:
- `maps.json` and `maps.min.json` - A JSON file containing all the images and their urls.
- `full` - Directory where `full` JPG images are generated.
- `medium` - Directory where `medium` JPG images are generated.
- `thumbnail` - Directory where `thumbnail` JPG images are generated.
- `webp/full` - Directory where `full` WEBP images are generated.
- `webp/medium` - Directory where `medium` WEBP images are generated.
- `webp/thumbnail` - Directory where `thumbnail` WEBP images are generated.

## Examples

#### I want to use full-sized image of the second course from kz_tangent in WEBP format
- https://github.com/kzglobalteam/cs2kz-images/raw/public/webp/full/kz_tangent/2.webp

#### I want to use medium-sized image of the fourth course from kz_alpha in JPG format
- https://github.com/kzglobalteam/cs2kz-images/raw/public/medium/kz_alpha/4.jpg

#### I want to retrieve all the map images and their urls as JSON
- https://github.com/kzglobalteam/cs2kz-images/raw/public/maps.json
- https://github.com/kzglobalteam/cs2kz-images/raw/public/maps.min.json

## Contributing
If you would like to add missing map images, follow the steps:
1. [Fork this repository](https://github.com/kzglobalteam/cs2kz-images/fork).
2. Upload the images to the `images` directory in your repository.
3. Commit and push your changes.
4. Create a pull request from your repository to here.

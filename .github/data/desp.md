How the images are built:

Each image is built automatically in the
[anyvm-org/redox-builder](https://github.com/anyvm-org/redox-builder)
repo's GitHub Actions: it downloads the official Redox OS harddrive
image, prepares it offline (console access and the anyvm runtime
support are injected into the image), verifies it by booting in QEMU,
and exports the disk as a compressed qcow2 image. No interactive
installer is run.

Upstream media: the official Redox OS release images from
https://static.redox-os.org/releases/ (project site:
https://www.redox-os.org/).

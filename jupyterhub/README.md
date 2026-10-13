# JupyterHub hub image

Builds the JupyterHub hub image from our fork of
[jupyterhub-fancy-profiles](https://github.com/rtmiz/jupyterhub-fancy-profiles)
and pushes it to Harbor and GHCR. Only the CI config lives here, so the fork
itself stays free of EODC-specific workflows.

## Configuration

All values live in [`build.env`](build.env):

| Key               | Meaning                                                  |
| ----------------- | -------------------------------------------------------- |
| `SOURCE_REPO`     | GitHub repo to build from                                |
| `SOURCE_REF`      | Branch, tag or commit built by default                   |
| `REGISTRY`        | Harbor registry host                                     |
| `IMAGE_NAME`      | `<project>/<image>` inside Harbor                        |
| `GHCR_IMAGE_NAME` | Image name under `ghcr.io/eodcgmbh/container-images/`    |
| `PLATFORMS`       | Comma-separated target platforms for buildx              |

Required repository secrets:

- `HARBOR_USERNAME`, `HARBOR_PASSWORD`: a Harbor robot account with push
  access to the target project.

GHCR uses the workflow's `GITHUB_TOKEN`, so it needs no extra secret.

## Running a build

Actions → **Build and publish JupyterHub hub image** → **Run workflow**. Leave
`ref` empty to build `SOURCE_REF`, or enter another branch, tag or commit of
the fork.

Each build is pushed to both registries with these tags:

- `sha-<short commit>`: the fork commit that was built.
- `<ref>`: the branch or tag name (e.g. `main-prod`). This tag moves with every build.

Builds of the default `SOURCE_REF` are releases and also get:

- `<year>.<month>.<n>` (e.g. `2026.10.2`): CalVer release tag. `n` is one
  higher than the highest tag for the current month (Vienna time) in Harbor,
  and starts again at `1` each month. Pin deployments to this tag.
- `latest`: the newest release.

Builds of any other `ref` get no release tags and don't move `latest`.

Builds don't start automatically when the fork changes. Start them by hand.

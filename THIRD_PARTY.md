# Third-party software in flypaper releases

flypaper's release page carries, next to flypaper's own binaries, unmodified
builds of:

## Beelzebub

- Project: https://github.com/beelzebub-labs/beelzebub
- Licence: GNU General Public License v3.0 (`LICENSE` in that repository)
- Version: tag `v3.10.0`, commit `a02d0354e19a01e97eeccaf1874419dcb05b94ca`
- Files: `beelzebub_linux_amd64`, `beelzebub_linux_arm64`
- Built by flypaper's CI (`.github/workflows/ci.yml`, job `release`) with
  `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X ...cli.Version=v3.10.0 -X ...cli.CommitSHA=a02d0354"`
  from an unmodified checkout of that tag. The build fails if the tag no
  longer points at that commit.

Corresponding source: the upstream repository at the tag and commit above,
`git clone --branch v3.10.0 https://github.com/beelzebub-labs/beelzebub.git`.
flypaper applies no patches. The service definition installed by
`install/web-honeypot.sh` (`configurations/services/http-80.yaml`) is
downloaded from the same tag at install time and used as is.

Beelzebub is installed only when `install/web-honeypot.sh` runs (the
installer's default). flypaper itself is MIT licensed and does not link to
Beelzebub; it reads Beelzebub's event log.

pkg_name=aws-signing-proxy
pkg_origin=irvingpop
pkg_version="0.2.0"
pkg_maintainer="The Chef Automate Maintainers <support@chef.io>"
pkg_license=('MIT')
pkg_source="https://github.com/nsdavidson/aws-signing-proxy.git"
pkg_dirname="$pkg_name"
pkg_deps=( )
pkg_build_deps=(
  core/git
  core/go
)
pkg_bin_dirs=(bin)
pkg_exports=(
  [http-port]=port
)
pkg_exposes=(http-port)
pkg_description="AWS Signing Proxy for ElasticSearch"
pkg_upstream_url="https://github.com/nsdavidson/aws-signing-proxy"

do_clean() {
  return 0
}

do_download() {
  rm -rf "$CACHE_PATH"
  git clone "$pkg_source" "$CACHE_PATH" --depth 1 --branch "v$pkg_version"
}

do_verify() {
  return 0
}

do_unpack() {
  return 0
}

do_prepare() {
  mkdir -pv "$CACHE_PATH/cache"
  export GOPATH="$CACHE_PATH/cache"
  build_line "Setting GOPATH=$GOPATH"
  export PATH="$PATH:$GOPATH/bin"
  build_line "Setting PATH=$PATH"
  export GOOS=linux
  build_line "Setting GOOS=$GOOS"
  GOARCH=amd64
  build_line "Setting GOARCH=$GOARCH"
}

do_build() {
  go get github.com/Masterminds/glide
  glide up
  glide install
  mkdir -pv "$CACHE_PATH/vendor/src"
  mv "$CACHE_PATH/vendor/"*.* "$CACHE_PATH/vendor/src"
  export GOPATH="$CACHE_PATH/vendor"
  build_line "Setting GOPATH=$GOPATH"
  go build -ldflags "-X main.VERSION=$pkg_version" -o "$pkg_prefix/bin/aws-signing-proxy" $CACHE_PATH/main.go
}

do_install() {
  return 0
}

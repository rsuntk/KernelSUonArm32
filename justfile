alias bk := build_ksud
alias bm := build_manager

build_ksud:
    cross build --target armv7-linux-androideabi --release --manifest-path ./userspace/ksud/Cargo.toml

build_manager: build_ksud
    cd manager && ./gradlew aDebug
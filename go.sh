#!/bin/bash

# pkill -f mocksql 2>/dev/null
# sleep 1

# rm -f /tmp/data/*.json 2>/dev/null

#/opt/kip/git/mocksql/target/release/mocksql /tmp/data

#/opt/kip/git/mocksql/target/release/mocksql --no-daemon /tmp/data

cargo build --release
cargo test --test integration

/mnt/share/mocksql/mocksql/target/release/mocksql --trace 2>&1 | tee /tmp/lkj



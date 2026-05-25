#!/bin/bash

cargo build --release
cargo test --test integration

./target/release/mocksql --trace 2>&1 | tee /tmp/mocksql.txt



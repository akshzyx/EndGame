#!/bin/bash

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
apt-get install musl-gcc
rustup target add x86_64-unknown-linux-musl

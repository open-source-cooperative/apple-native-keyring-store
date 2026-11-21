#!/usr/bin/env bash
#
# test the protected code in the iOS simulator
#
export RUSTFLAGS="-D warnings -C link-arg=-Wl,-sectcreate,__TEXT,__entitlements,$(dirname $0)/ios-simulator.entitlements"
bin=$(env cargo test --lib --no-run --target aarch64-apple-ios-sim --features protected --message-format=json \
            | jq -r 'select(.profile.test == true and .executable != null) | .executable')
if [ -z "$bin" ]; then
  echo "No executable produced for simulator"
  exit 1
fi
if [ "$(printf '%s\n' "$bin" | wc -l)" -ne 1 ]; then
  echo "Unknown executable produced for simulator: $bin"
  exit 1
fi
udid=$(xcrun simctl list devices available -j \
  | jq -r '[.devices | to_entries[] | select(.key | contains("SimRuntime.iOS")) | .value[] | select(.name | startswith("iPhone"))][0].udid // empty')
if [ -z "$udid" ]; then
  echo "No UDID found for simulator"
fi
echo "Booting simulator $udid"
xcrun simctl boot "$udid"
xcrun simctl bootstatus "$udid"
echo "Running $bin with a timeout of 5 minutes"
timeout 5m xcrun simctl spawn "$udid" "$bin"
echo "Shutting down simulator $udid"
xcrun simctl shutdown "$udid"
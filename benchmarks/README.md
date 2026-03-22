# Firmware 

## Existing firmware binaries

To aid comparisons, we use the exact binary blobs and configurations for existing binaries from Fuzzware, obtained from: 

[fuzzware-experiments/02-comparison-with-state-of-the-art](
https://github.com/fuzzware-fuzzer/fuzzware-experiments/tree/cfe63a941ce89fe4ce7c8295618e9ed3bcc4ff53/02-comparison-with-state-of-the-art)

## New firmware binaries

MultiFuzz includes 3 additional binaries for benchmarking and crash analysis. These can be reproduced using the `./build_new_binaries.sh` (requires Docker). After the running the build script you should end up with the following binaries (placed in the `new` folder):

| SHA256                                                           | binary
| ---------------------------------------------------------------- | ------------------
| b422ea45c960705ce28d5f41f2e9aef972c8afcb2cbdb057de202aaaed14304f | ccn-lite-relay.elf
| fca1d84f8acce22603bbfb2c349561866926b8b971e297fe75fc1f66a11f289c | filesystem.elf
| 444e9576e8b85f985643738ffb7358e4e7857c5ed389b302a05cd04a1ab21425 | gnrc_networking.elf

To allow comparisons to Fuzzware, we use the `fuzzware genconfig` command from [Fuzzware]() to generate the configurations.


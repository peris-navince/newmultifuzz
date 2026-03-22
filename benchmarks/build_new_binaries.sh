#!/bin/bash

git clone https://github.com/RIOT-OS/RIOT RIOT 

# 9142d9c37597c665fa704fe00ec8e377 is the exact commit used for building the binaries
# 'git reset' is required (instead of 'git checkout') to avoid differences in the string output 
# ensuring 100% reproducable binaries.
cd RIOT && git reset --hard 9142d9c37597c665fa704fe00ec8e377 && cd ..

docker pull riot/riotbuild:2023.01

# Note: `DISABLE_MODULE=cortexm_fpu` is required to allow comparison with Fuzzware.

# ccn-lite-relay
docker run --rm \
    --mount type=bind,source="$PWD/RIOT,target=/RIOT" \
    riot/riotbuild \
    /bin/sh -c 'cd /RIOT; make -j8 -C examples/ccn-lite-relay DISABLE_MODULE=cortexm_fpu BOARD=nrf52dk'

mkdir -p new/riot-ccn-lite-relay 
cp ./RIOT/examples/ccn-lite-relay/bin/nrf52dk/ccn-lite-relay.elf new/riot-ccn-lite-relay/ccn-lite-relay.elf

# gnrc_networking
docker run --rm \
    --mount type=bind,source="$PWD/RIOT,target=/RIOT" \
    riot/riotbuild \
    /bin/sh -c 'cd /RIOT; make -j8 -C examples/gnrc_networking DISABLE_MODULE=cortexm_fpu BOARD=stm32f3discovery'

mkdir -p new/riot-gnrc_networking 
cp ./RIOT/examples/gnrc_networking/bin/stm32f3discovery/gnrc_networking.elf new/riot-gnrc_networking/gnrc_networking.elf

# filesystem
docker run --rm \
    --mount type=bind,source="$PWD/RIOT,target=/RIOT" \
    riot/riotbuild \
    /bin/sh -c 'cd /RIOT; make -j8 -C examples/filesystem DISABLE_MODULE=cortexm_fpu BOARD=stm32f3discovery'

mkdir -p new/riot-filesystem 
cp ./RIOT/examples/filesystem/bin/stm32f3discovery/filesystem.elf new/riot-filesystem/filesystem.elf


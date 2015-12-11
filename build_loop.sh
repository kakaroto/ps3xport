#!/bin/sh

if test -z $1 ; then
   name="test_loop"
else
   name=$1
fi

ppu-gcc -L$PS3DEV/ppu/ppu/lib -L$PSL1GHT/ppu/lib -I$PS3DEV/ppu/ppu/include -I$PSL1GHT/ppu/include/ udp_printf.c -I. $name.c -o $name.elf -lnet -lsysmodule && sprxlinker $name.elf && make_self $name.elf $name.self && cp $name.self pkg/USRDIR/EBOOT.BIN && pkg.py --contentid UP0001-TEST00000-0000000000000000 pkg/ $name.pkg && \
make_self_npdrm_sc $name.elf pkg/USRDIR/EBOOT.BIN UP0001-TEST00000-0000000000000000 && pkg.py --contentid UP0001-TEST00000-0000000000000000 pkg/ $name.npdrm.pkg 

make PLAT=mpxlx2160acrx08 all fip pbl BOOT_MODE=sd RCW=$HH/rcw/mpxlx2160a/sd/rcw_R2_2000_700_2666_19_5_2-sd.bin BL33=$HH/u-boot-qoriq/u-boot.bin
sudo dd if=build/mpxlx2160acrx08/release/bl2_sd.pbl conv=notrunc,fsync of=/dev/sdb bs=512 seek=8
sudo dd if=build/mpxlx2160acrx08/release/fip.bin of=/dev/sdb conv=notrunc,fsync bs=512 seek=2048
sudo dd if=$HH/fip_ddr_all.bin of=/dev/sdb conv=notrunc,fsync bs=512 seek=16384
sync

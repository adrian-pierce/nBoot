all:
	@clear
	@rm -rf BUILD
	@mkdir -p BUILD/EFI/BOOT

	@cargo build --release --target x86_64-unknown-uefi
	@cp target/x86_64-unknown-uefi/release/nBoot.efi BUILD/EFI/BOOT/BOOTX64.EFI

test:
	@clear
	@rm -rf BUILD
	@mkdir -p BUILD/EFI/BOOT

	@cargo build --release --target x86_64-unknown-uefi
	@cp target/x86_64-unknown-uefi/release/nBoot.efi BUILD/EFI/BOOT/BOOTX64.EFI
	@cp /usr/share/edk2/x64/OVMF_VARS.4m.fd BUILD/OVMF_VARS.4m.fd

	@qemu-system-x86_64 -enable-kvm -net none -m 1024 -serial stdio \
		-drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
		-drive if=pflash,format=raw,file=BUILD/OVMF_VARS.4m.fd \
		-drive file=fat:rw:BUILD,format=raw \

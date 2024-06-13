.Phony: main linux_bench
build clone:
		cargo build --release --bin clone_vm_no_clone_vm

clone:
		cargo run --release --bin clone_vm_no_clone_vm

clone trace:
	RUST_BACKTRACE=1 cargo run --release --bin clone_vm_no_clone_vm

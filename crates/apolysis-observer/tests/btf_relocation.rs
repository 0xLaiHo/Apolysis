// SPDX-License-Identifier: Apache-2.0

#[test]
#[ignore = "requires readable host BTF and make build-ebpf; does not require root"]
fn observer_object_relocates_against_running_kernel() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    let bytes = std::fs::read(root.join("target/ebpf/apolysis_observer.bpf.o"))
        .expect("run make build-ebpf before this opt-in relocation gate");
    let mut object = aya_obj::Object::parse(&bytes).expect("parse built observer ELF");
    let kernel_btf = aya_obj::btf::Btf::from_sys_fs().expect("read running kernel BTF");
    object
        .relocate_btf(&kernel_btf)
        .expect("all observer programs must relocate before loading into the kernel");
}

use binscout::disasm::{Arch, Operand, disasm_range, stack_slot};
use binscout::ir::{IrOp, lift, resolve_const_indirect};

fn x86_64_one(bytes: &[u8], va: u64) -> binscout::disasm::Insn {
    let insns = disasm_range(Arch::X86_64, bytes, va, 8).expect("x86_64 decodes");
    assert_eq!(insns.len(), 1, "{bytes:02x?}");
    insns.into_iter().next().unwrap()
}

#[test]
fn x86_64_mov_imm_has_typed_operands() {
    // mov rax, 0x1234
    let insn = x86_64_one(&[0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00], 0x1000);
    assert_eq!(insn.mnem, "mov");
    assert_eq!(insn.ops, ["rax", "0x1234"]);
    assert_eq!(insn.operands.len(), 2);
    assert!(matches!(
        &insn.operands[0],
        Operand::Reg { reg, bits: 64 } if reg == "rax"
    ));
    assert!(matches!(
        &insn.operands[1],
        Operand::Imm { value: 0x1234, .. }
    ));
    // Lift keeps strings and clones the typed operands.
    let rows = lift(Arch::X86_64, &insn);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].op, IrOp::Copy);
    assert_eq!(rows[0].inputs, ["0x1234"]);
    assert_eq!(rows[0].outputs, ["rax"]);
    assert_eq!(rows[0].operands, insn.operands);
}

#[test]
fn x86_64_mem_reports_signed_disp_and_stack_slot() {
    // mov rax, [rbp-0x10]
    let insn = x86_64_one(&[0x48, 0x8b, 0x45, 0xf0], 0x1000);
    assert_eq!(insn.operands.len(), 2);
    assert!(matches!(
        &insn.operands[0],
        Operand::Reg { reg, .. } if reg == "rax"
    ));
    let Operand::Mem {
        base,
        index,
        scale,
        disp,
        bits,
        segment,
    } = &insn.operands[1]
    else {
        panic!("second operand is mem, got {:?}", insn.operands[1]);
    };
    assert_eq!(base.as_deref(), Some("rbp"));
    assert_eq!(index, &None);
    assert_eq!(*scale, 1);
    assert_eq!(*disp, -16);
    assert_eq!(*segment, None);
    assert!(*bits > 0);
    let slot = stack_slot(&insn.operands[1]).expect("rbp slot");
    assert_eq!(slot, ("rbp", -16, *bits));
}

#[test]
fn x86_64_indexed_mem_has_no_stack_slot() {
    // mov rax, [rbx+rcx*4]: index present, so no plain stack slot.
    let insn = x86_64_one(&[0x48, 0x8b, 0x04, 0x8b], 0x1000);
    let mem = insn
        .operands
        .iter()
        .find(|o| matches!(o, Operand::Mem { .. }))
        .expect("has mem operand");
    assert!(stack_slot(mem).is_none());
    let Operand::Mem { base, index, .. } = mem else {
        unreachable!()
    };
    assert_eq!(base.as_deref(), Some("rbx"));
    assert_eq!(index.as_deref(), Some("rcx"));
}

#[test]
fn x86_64_indirect_call_has_single_reg_operand() {
    let insn = x86_64_one(&[0xff, 0xd0], 0x1000);
    assert_eq!(insn.mnem, "call");
    assert_eq!(insn.branch_target, None);
    assert_eq!(insn.operands.len(), 1);
    assert!(matches!(
        &insn.operands[0],
        Operand::Reg { reg, .. } if reg == "rax"
    ));
    let rows = lift(Arch::X86_64, &insn);
    assert_eq!(rows[0].op, IrOp::Call);
    assert_eq!(rows[0].target, None);
    assert_eq!(rows[0].operands.len(), 1);
}

#[test]
fn const_prop_resolves_mov_then_indirect_call() {
    // mov rax, 0x1234; call rax
    let mov = x86_64_one(&[0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00], 0x1000);
    let call = x86_64_one(&[0xff, 0xd0], 0x1007);
    let mut rows = lift(Arch::X86_64, &mov);
    rows.extend(lift(Arch::X86_64, &call));
    let hits = resolve_const_indirect(&rows);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].addr, 0x1007);
    assert_eq!(hits[0].reg, "rax");
    assert_eq!(hits[0].value, 0x1234);
}

#[test]
fn const_prop_kills_on_overwrite() {
    // mov rax, 1; mov rax, rbx; call rax -> killed, no hit.
    let mov1 = x86_64_one(&[0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00], 0x1000);
    // mov rax, rbx
    let mov2 = x86_64_one(&[0x48, 0x89, 0xd8], 0x1007);
    let call = x86_64_one(&[0xff, 0xd0], 0x100a);
    let mut rows = lift(Arch::X86_64, &mov1);
    rows.extend(lift(Arch::X86_64, &mov2));
    rows.extend(lift(Arch::X86_64, &call));
    assert!(resolve_const_indirect(&rows).is_empty());
}

#[test]
fn const_prop_chains_reg_copies() {
    // mov rax, 0x10; mov rbx, rax; jmp rbx -> resolves via the chain.
    let mov1 = x86_64_one(&[0x48, 0xc7, 0xc0, 0x10, 0x00, 0x00, 0x00], 0x1000);
    // mov rbx, rax
    let mov2 = x86_64_one(&[0x48, 0x89, 0xc3], 0x1007);
    // jmp rbx
    let jmp = x86_64_one(&[0xff, 0xe3], 0x100a);
    let mut rows = lift(Arch::X86_64, &mov1);
    rows.extend(lift(Arch::X86_64, &mov2));
    rows.extend(lift(Arch::X86_64, &jmp));
    let hits = resolve_const_indirect(&rows);
    assert_eq!(hits.len(), 1);
    assert_eq!(
        (hits[0].addr, hits[0].reg.as_str(), hits[0].value),
        (0x100a, "rbx", 0x10)
    );
}

#[test]
fn const_prop_ignores_direct_calls_and_subregisters() {
    // Direct call never resolves (has a target).
    let call = x86_64_one(&[0xe8, 0, 0, 0, 0], 0x2000);
    let rows = lift(Arch::X86_64, &call);
    assert_eq!(rows[0].target, Some(0x2005));
    assert!(resolve_const_indirect(&rows).is_empty());

    // mov eax, 1 does not resolve a later call rax (exact-name only).
    let mov = x86_64_one(&[0xb8, 0x01, 0x00, 0x00, 0x00], 0x3000);
    let call_rax = x86_64_one(&[0xff, 0xd0], 0x3005);
    let mut rows = lift(Arch::X86_64, &mov);
    rows.extend(lift(Arch::X86_64, &call_rax));
    assert!(resolve_const_indirect(&rows).is_empty());
}

#[test]
fn non_x86_rows_carry_no_structured_operands() {
    // ldr x0, [x1] decodes but reports an empty typed vec.
    let insns =
        disasm_range(Arch::Aarch64, &[0x20, 0x00, 0x40, 0xf9], 0x4000, 8).expect("aarch64 decodes");
    assert!(insns[0].operands.is_empty());
    let rows = lift(Arch::Aarch64, &insns[0]);
    assert!(rows[0].operands.is_empty());
    assert!(resolve_const_indirect(&rows).is_empty());
}

#[test]
fn legacy_json_without_operands_still_decodes() {
    let insn: binscout::disasm::Insn = serde_json::from_value(serde_json::json!({
        "addr": 4096, "size": 1, "bytes": [144], "mnem": "nop", "ops": [],
        "branch_target": null, "mem_target": null,
    }))
    .expect("legacy insn");
    assert!(insn.operands.is_empty());

    let ir: binscout::ir::IrInsn = serde_json::from_value(serde_json::json!({
        "addr": 8192, "op": "Return", "inputs": [], "outputs": [],
        "target": null, "warning": null,
    }))
    .expect("legacy ir");
    assert!(ir.operands.is_empty());
    // Empty vecs stay omitted so old goldens keep passing.
    let v = serde_json::to_value(&ir).expect("json");
    assert!(v.get("operands").is_none());
}

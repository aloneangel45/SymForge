package xref

import (
	"encoding/hex"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

type arm64Step struct {
	insnVA    uint64
	dataVA    uint64
	ptrReg    int // 0..30 for X0..X30/W0..W30, -1 if none
	hasDataVA bool

	immVal int64
	immReg int // 0..30
	hasImm bool
}

// arm64GPRIndex maps X0..X30 and W0..W30 (including RegSP wrappers) to 0..30, or -1 for SP/ZR/SIMD.
func arm64GPRIndex(arg arm64asm.Arg) int {
	switch r := arg.(type) {
	case arm64asm.Reg:
		if arm64asm.X0 <= r && r <= arm64asm.X30 {
			return int(r - arm64asm.X0)
		}
		if arm64asm.W0 <= r && r <= arm64asm.W30 {
			return int(r - arm64asm.W0)
		}
	case arm64asm.RegSP:
		reg := arm64asm.Reg(r)
		if arm64asm.X0 <= reg && reg <= arm64asm.X30 {
			return int(reg - arm64asm.X0)
		}
		if arm64asm.W0 <= reg && reg <= arm64asm.W30 {
			return int(reg - arm64asm.W0)
		}
	}
	return -1
}

// decodeARM64MemImmOffset extracts the effective byte offset for a MemImmediate operand
// directly from the ARMv8-A 32-bit instruction word.
func decodeARM64MemImmOffset(enc uint32, mem arm64asm.MemImmediate) (int64, bool) {
	if mem.Mode == arm64asm.AddrPostIndex || mem.Mode == arm64asm.AddrPostReg {
		// Post-index accesses [Rn] before adding the post-offset.
		return 0, true
	}
	// Unsigned 12-bit scaled immediate load/store: (enc & 0x3b000000) == 0x39000000
	if (enc & 0x3b000000) == 0x39000000 {
		imm12 := int64((enc >> 10) & 0xfff)
		if (enc & 0x04000000) != 0 {
			// SIMD&FP load/store: scale = size | (opc<1> << 2)
			scale := ((enc >> 30) & 0x3) | (((enc >> 23) & 0x1) << 2)
			if scale <= 4 {
				return imm12 << scale, true
			}
			return 0, false
		}
		scale := (enc >> 30) & 0x3
		return imm12 << scale, true
	}
	// Unscaled 9-bit signed immediate / pre-index: (enc & 0x3b200000) == 0x38000000
	if (enc & 0x3b200000) == 0x38000000 {
		imm9 := int64(int32(enc<<11) >> 23)
		return imm9, true
	}
	// Load/store pair (LDP/STP): (enc & 0x3a000000) == 0x28000000
	if (enc & 0x3a000000) == 0x28000000 {
		imm7 := int64(int32(enc<<10) >> 25)
		if (enc & 0x04000000) != 0 {
			scale := 2 + ((enc >> 30) & 0x3)
			return imm7 << scale, true
		}
		scale := 2 + ((enc >> 31) & 0x1)
		return imm7 << scale, true
	}
	return 0, false
}

// extractARM64MovImmediate extracts small positive integer constants (4..2048) loaded into GPRs.
func extractARM64MovImmediate(inst arm64asm.Inst) (regIdx int, val int64, ok bool) {
	enc := inst.Enc
	// Move wide immediate MOVZ / MOV <Xd|Wd>, #<imm>: (enc & 0x7f800000) == 0x52800000
	if (enc & 0x7f800000) == 0x52800000 {
		rd := int(enc & 0x1f)
		if rd >= 31 {
			return -1, 0, false
		}
		hw := ((enc >> 21) & 0x3) * 16
		if hw >= 64 {
			return -1, 0, false
		}
		imm16 := uint64((enc >> 5) & 0xffff)
		uval := imm16 << hw
		if uval >= 4 && uval <= maxInsnSliceStrLen {
			return rd, int64(uval), true
		}
		return -1, 0, false
	}

	// Logical bitmask MOV / MOVZ decoded as arm64asm.MOV with Imm or Imm64 in Args[1].
	if inst.Op == arm64asm.MOV || inst.Op == arm64asm.MOVZ {
		rd := arm64GPRIndex(inst.Args[0])
		if rd < 0 {
			return -1, 0, false
		}
		switch v := inst.Args[1].(type) {
		case arm64asm.Imm:
			if v.Imm >= 4 && v.Imm <= maxInsnSliceStrLen {
				return rd, int64(v.Imm), true
			}
		case arm64asm.Imm64:
			if v.Imm >= 4 && v.Imm <= maxInsnSliceStrLen {
				return rd, int64(v.Imm), true
			}
		}
	}
	return -1, 0, false
}

func isARM64NonClobberFirstArg(op arm64asm.Op) bool {
	switch op {
	case arm64asm.STR, arm64asm.STRB, arm64asm.STRH, arm64asm.STP,
		arm64asm.STUR, arm64asm.STURB, arm64asm.STURH,
		arm64asm.CMP, arm64asm.CMN, arm64asm.TST,
		arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ,
		arm64asm.B, arm64asm.BL, arm64asm.BR, arm64asm.BLR, arm64asm.RET:
		return true
	default:
		return false
	}
}

func (a *analyzer) scanARM64Function(fnIdx int, fnEntry uint64, code []byte) {
	steps := a.armScratch[:0]
	limit := len(code) &^ 3
	fnEnd := fnEntry + uint64(limit)

	var (
		regPage     [31]uint64
		regInsnVA   [31]uint64
		regStepIdx  [31]int
		regValid    [31]bool
		regConsumed [31]bool
	)

	flushUnconsumedADRP := func(r int) {
		if r >= 0 && r < 31 && regValid[r] && !regConsumed[r] {
			va := regPage[r]
			if a.lb.IsReadableVA(va) && !a.lb.IsCodeVA(va) {
				idx := regStepIdx[r]
				if idx >= 0 && idx < len(steps) && !steps[idx].hasDataVA {
					steps[idx].dataVA = va
					steps[idx].ptrReg = r
					steps[idx].hasDataVA = true
				}
			}
		}
	}

	for off := 0; off < limit; off += 4 {
		insnVA := fnEntry + uint64(off)
		inst, err := arm64asm.Decode(code[off : off+4])
		var st arm64Step
		st.insnVA = insnVA
		st.ptrReg = -1
		st.immReg = -1

		if err != nil {
			steps = append(steps, st)
			continue
		}

		// 1. Direct BL / tail B calls.
		if inst.Op == arm64asm.BL {
			if pcrel, ok := inst.Args[0].(arm64asm.PCRel); ok {
				targetVA := uint64(int64(insnVA) + int64(pcrel))
				a.recordCall(fnIdx, targetVA)
			}
			// Flush any page-aligned ADRP (offset == 0) in caller-saved registers X0..X18 before call clobbers them.
			for r := 0; r <= 18; r++ {
				flushUnconsumedADRP(r)
				regValid[r] = false
			}
			steps = append(steps, st)
			continue
		}

		if inst.Op == arm64asm.B {
			// Unconditional B has PCRel in Args[0]; conditional B.cond has Cond in Args[0].
			if pcrel, ok := inst.Args[0].(arm64asm.PCRel); ok {
				targetVA := uint64(int64(insnVA) + int64(pcrel))
				if targetVA < fnEntry || targetVA >= fnEnd {
					a.recordCall(fnIdx, targetVA)
				}
				for r := 0; r <= 18; r++ {
					flushUnconsumedADRP(r)
				}
			}
			steps = append(steps, st)
			continue
		}

		if inst.Op == arm64asm.BLR || inst.Op == arm64asm.BR {
			rn := arm64GPRIndex(inst.Args[0])
			if rn >= 0 && regValid[rn] {
				a.recordCall(fnIdx, regPage[rn])
				regConsumed[rn] = true
			}
			for r := 0; r <= 18; r++ {
				flushUnconsumedADRP(r)
				if inst.Op == arm64asm.BLR {
					regValid[r] = false
				}
			}
			steps = append(steps, st)
			continue
		}

		if inst.Op == arm64asm.RET {
			for r := 0; r < 31; r++ {
				flushUnconsumedADRP(r)
				regValid[r] = false
			}
			steps = append(steps, st)
			continue
		}

		// 2. ADRP Xd, page -> arm64asm PCRel already includes the << 12 page shift.
		if inst.Op == arm64asm.ADRP {
			rd := arm64GPRIndex(inst.Args[0])
			if pcrel, ok := inst.Args[1].(arm64asm.PCRel); ok && rd >= 0 {
				flushUnconsumedADRP(rd)
				pageBase := (insnVA & ^uint64(0xfff)) + uint64(int64(pcrel))
				regPage[rd] = pageBase
				regInsnVA[rd] = insnVA
				regStepIdx[rd] = len(steps)
				regValid[rd] = true
				regConsumed[rd] = false
			}
			steps = append(steps, st)
			continue
		}

		// 3. ADR Xd, label -> exact PC-relative byte address.
		if inst.Op == arm64asm.ADR {
			rd := arm64GPRIndex(inst.Args[0])
			if pcrel, ok := inst.Args[1].(arm64asm.PCRel); ok {
				if rd >= 0 {
					flushUnconsumedADRP(rd)
				}
				targetVA := uint64(int64(insnVA) + int64(pcrel))
				st.dataVA = targetVA
				st.ptrReg = rd
				st.hasDataVA = true
				if rd >= 0 {
					regPage[rd] = targetVA
					regInsnVA[rd] = insnVA
					regStepIdx[rd] = len(steps)
					regValid[rd] = true
					regConsumed[rd] = true
				}
			}
			steps = append(steps, st)
			continue
		}

		// 4. ADD Xd, Xn, #imm12{, LSL #12} -> complete ADRP + ADD address calculation.
		if inst.Op == arm64asm.ADD && (inst.Enc&0x7f000000) == 0x11000000 {
			rd := arm64GPRIndex(inst.Args[0])
			rn := arm64GPRIndex(inst.Args[1])
			sh := (inst.Enc >> 22) & 0x3
			imm12 := uint64((inst.Enc >> 10) & 0xfff)
			if sh == 1 {
				imm12 <<= 12
			}
			if rn >= 0 && regValid[rn] && (sh == 0 || sh == 1) {
				targetVA := regPage[rn] + imm12
				regConsumed[rn] = true
				st.dataVA = targetVA
				st.ptrReg = rd
				st.hasDataVA = true
				if rd >= 0 {
					regPage[rd] = targetVA
					regInsnVA[rd] = insnVA
					regStepIdx[rd] = len(steps)
					regValid[rd] = true
					regConsumed[rd] = true
				}
			} else if rd >= 0 {
				flushUnconsumedADRP(rd)
				regValid[rd] = false
			}
			steps = append(steps, st)
			continue
		}

		// 5. LDR / LDRB / LDRH / LDRSW / LDP: resolve ADRP + LDR [Xn, #imm] and PC-relative literal LDR.
		switch inst.Op {
		case arm64asm.LDR, arm64asm.LDRB, arm64asm.LDRH, arm64asm.LDRSW:
			rt := arm64GPRIndex(inst.Args[0])
			switch m := inst.Args[1].(type) {
			case arm64asm.PCRel:
				targetVA := uint64(int64(insnVA) + int64(m))
				st.dataVA = targetVA
				st.ptrReg = rt
				st.hasDataVA = true
				if rt >= 0 {
					flushUnconsumedADRP(rt)
					if ptr, ok := a.lb.ReadPtrAtVA(targetVA); ok && ptr != 0 {
						regPage[rt] = ptr
						regInsnVA[rt] = insnVA
						regStepIdx[rt] = len(steps)
						regValid[rt] = true
						regConsumed[rt] = true
					} else {
						regValid[rt] = false
					}
				}
			case arm64asm.MemImmediate:
				rn := arm64GPRIndex(m.Base)
				if rn >= 0 && regValid[rn] {
					if disp, ok := decodeARM64MemImmOffset(inst.Enc, m); ok {
						targetVA := uint64(int64(regPage[rn]) + disp)
						regConsumed[rn] = true
						st.dataVA = targetVA
						st.ptrReg = rt
						st.hasDataVA = true
						if rt >= 0 {
							if inst.Op == arm64asm.LDR {
								if ptr, ok := a.lb.ReadPtrAtVA(targetVA); ok && ptr != 0 {
									regPage[rt] = ptr
									regInsnVA[rt] = insnVA
									regStepIdx[rt] = len(steps)
									regValid[rt] = true
									regConsumed[rt] = true
									steps = append(steps, st)
									continue
								}
							}
							regValid[rt] = false
						}
						steps = append(steps, st)
						continue
					}
				}
				if rt >= 0 {
					flushUnconsumedADRP(rt)
					regValid[rt] = false
				}
			default:
				if rt >= 0 {
					flushUnconsumedADRP(rt)
					regValid[rt] = false
				}
			}
			steps = append(steps, st)
			continue

		case arm64asm.LDP:
			rt1 := arm64GPRIndex(inst.Args[0])
			rt2 := arm64GPRIndex(inst.Args[1])
			if m, ok := inst.Args[2].(arm64asm.MemImmediate); ok {
				rn := arm64GPRIndex(m.Base)
				if rn >= 0 && regValid[rn] {
					if disp, ok := decodeARM64MemImmOffset(inst.Enc, m); ok {
						targetVA := uint64(int64(regPage[rn]) + disp)
						regConsumed[rn] = true
						st.dataVA = targetVA
						st.ptrReg = rt1
						st.hasDataVA = true
					}
				}
			}
			if rt1 >= 0 {
				regValid[rt1] = false
			}
			if rt2 >= 0 {
				regValid[rt2] = false
			}
			steps = append(steps, st)
			continue
		}

		// 6. MOV / MOVZ immediate loads (for Go string length register pairing).
		if immReg, immVal, ok := extractARM64MovImmediate(inst); ok {
			flushUnconsumedADRP(immReg)
			regValid[immReg] = false
			st.immReg = immReg
			st.immVal = immVal
			st.hasImm = true
			steps = append(steps, st)
			continue
		}

		// 7. Register-to-register MOV propagation (MOV Xd, Xn).
		if inst.Op == arm64asm.MOV {
			rd := arm64GPRIndex(inst.Args[0])
			rn := arm64GPRIndex(inst.Args[1])
			if rd >= 0 && rn >= 0 {
				if rd != rn {
					flushUnconsumedADRP(rd)
				}
				if regValid[rn] {
					regPage[rd] = regPage[rn]
					regInsnVA[rd] = regInsnVA[rn]
					regStepIdx[rd] = regStepIdx[rn]
					regValid[rd] = true
					regConsumed[rd] = regConsumed[rn]
				} else {
					regValid[rd] = false
				}
				steps = append(steps, st)
				continue
			}
		}

		// 8. Invalidate destination GPR on clobbering instructions.
		if !isARM64NonClobberFirstArg(inst.Op) {
			if rd := arm64GPRIndex(inst.Args[0]); rd >= 0 {
				flushUnconsumedADRP(rd)
				regValid[rd] = false
			}
		}

		steps = append(steps, st)
	}

	for r := 0; r < 31; r++ {
		flushUnconsumedADRP(r)
	}

	// Second micro-pass: check [-3, +3] instruction window around each resolved data VA for Go string length.
	for i := range steps {
		st := &steps[i]
		if !st.hasDataVA {
			continue
		}
		lo := i - 3
		if lo < 0 {
			lo = 0
		}
		hi := i + 3
		if hi >= len(steps) {
			hi = len(steps) - 1
		}

		pairedReg := -1
		if st.ptrReg >= 0 && st.ptrReg < 30 {
			pairedReg = st.ptrReg + 1
		}

		sliced := false
		// Pass A: exact Go ARM64 ABI paired register X(k+1) / W(k+1).
		if pairedReg >= 0 {
			for delta := 1; delta <= 3 && !sliced; delta++ {
				for _, j := range [2]int{i + delta, i - delta} {
					if j < lo || j > hi || !steps[j].hasImm {
						continue
					}
					if steps[j].immReg == pairedReg {
						if a.strExt.trySliceInstructionString(st.dataVA, int(steps[j].immVal), true) {
							sliced = true
							break
						}
					}
				}
			}
		}

		// Pass B: fallback nearest MOV reg, imm in [-3, +3].
		if !sliced {
			for delta := 1; delta <= 3 && !sliced; delta++ {
				for _, j := range [2]int{i + delta, i - delta} {
					if j < lo || j > hi || !steps[j].hasImm {
						continue
					}
					if st.ptrReg >= 0 && steps[j].immReg == st.ptrReg {
						continue
					}
					if a.strExt.trySliceInstructionString(st.dataVA, int(steps[j].immVal), false) {
						sliced = true
						break
					}
				}
			}
		}

		a.recordDataRef(fnIdx, st.insnVA, st.dataVA)
	}

	a.armScratch = steps[:0]
}

func disassembleARM64(
	lb *loader.LoadedBinary,
	fn model.Function,
	code []byte,
	symMap map[uint64]string,
	strMap map[uint64]string,
	maxInsns int,
) []model.DisasmInstruction {
	limit := len(code) &^ 3
	out := make([]model.DisasmInstruction, 0, minIntVal(maxInsns, 128))

	var (
		regPage  [31]uint64
		regValid [31]bool
	)

	for off := 0; off < limit && len(out) < maxInsns; off += 4 {
		insnVA := fn.Entry + uint64(off)
		rawBytes := code[off : off+4]
		inst, err := arm64asm.Decode(rawBytes)
		if err != nil {
			out = append(out, model.DisasmInstruction{
				Addr:     insnVA,
				BytesHex: hex.EncodeToString(rawBytes),
				Text:     ".word 0x" + hex.EncodeToString(rawBytes),
			})
			continue
		}

		text := strings.ToLower(arm64asm.GNUSyntax(inst))
		var targetVA uint64

		switch inst.Op {
		case arm64asm.BL:
			if pcrel, ok := inst.Args[0].(arm64asm.PCRel); ok {
				targetVA = uint64(int64(insnVA) + int64(pcrel))
			}
			for r := 0; r <= 18; r++ {
				regValid[r] = false
			}

		case arm64asm.B:
			if pcrel, ok := inst.Args[0].(arm64asm.PCRel); ok {
				targetVA = uint64(int64(insnVA) + int64(pcrel))
			} else if pcrel, ok := inst.Args[1].(arm64asm.PCRel); ok {
				targetVA = uint64(int64(insnVA) + int64(pcrel))
			}

		case arm64asm.CBZ, arm64asm.CBNZ:
			if pcrel, ok := inst.Args[1].(arm64asm.PCRel); ok {
				targetVA = uint64(int64(insnVA) + int64(pcrel))
			}

		case arm64asm.TBZ, arm64asm.TBNZ:
			if pcrel, ok := inst.Args[2].(arm64asm.PCRel); ok {
				targetVA = uint64(int64(insnVA) + int64(pcrel))
			}

		case arm64asm.ADRP:
			rd := arm64GPRIndex(inst.Args[0])
			if pcrel, ok := inst.Args[1].(arm64asm.PCRel); ok {
				pageBase := (insnVA & ^uint64(0xfff)) + uint64(int64(pcrel))
				targetVA = pageBase
				if rd >= 0 {
					regPage[rd] = pageBase
					regValid[rd] = true
				}
			}

		case arm64asm.ADR:
			rd := arm64GPRIndex(inst.Args[0])
			if pcrel, ok := inst.Args[1].(arm64asm.PCRel); ok {
				targetVA = uint64(int64(insnVA) + int64(pcrel))
				if rd >= 0 {
					regPage[rd] = targetVA
					regValid[rd] = true
				}
			}

		case arm64asm.ADD:
			rd := arm64GPRIndex(inst.Args[0])
			if (inst.Enc & 0x7f000000) == 0x11000000 {
				rn := arm64GPRIndex(inst.Args[1])
				sh := (inst.Enc >> 22) & 0x3
				imm12 := uint64((inst.Enc >> 10) & 0xfff)
				if sh == 1 {
					imm12 <<= 12
				}
				if rn >= 0 && regValid[rn] && (sh == 0 || sh == 1) {
					targetVA = regPage[rn] + imm12
					if rd >= 0 {
						regPage[rd] = targetVA
						regValid[rd] = true
					}
					break
				}
			}
			if rd >= 0 {
				regValid[rd] = false
			}

		case arm64asm.LDR, arm64asm.LDRB, arm64asm.LDRH, arm64asm.LDRSW:
			rt := arm64GPRIndex(inst.Args[0])
			switch m := inst.Args[1].(type) {
			case arm64asm.PCRel:
				targetVA = uint64(int64(insnVA) + int64(m))
			case arm64asm.MemImmediate:
				rn := arm64GPRIndex(m.Base)
				if rn >= 0 && regValid[rn] {
					if disp, ok := decodeARM64MemImmOffset(inst.Enc, m); ok {
						targetVA = uint64(int64(regPage[rn]) + disp)
					}
				}
			}
			if rt >= 0 {
				regValid[rt] = false
			}

		default:
			if !isARM64NonClobberFirstArg(inst.Op) {
				if rd := arm64GPRIndex(inst.Args[0]); rd >= 0 {
					regValid[rd] = false
				}
			}
		}

		di := model.DisasmInstruction{
			Addr:       insnVA,
			BytesHex:   hex.EncodeToString(rawBytes),
			Text:       text,
			TargetAddr: targetVA,
		}
		if targetVA != 0 {
			if symMap != nil {
				di.TargetSymbol = symMap[targetVA]
			}
			if strMap != nil {
				di.StringRef = strMap[targetVA]
			}
		}
		out = append(out, di)
	}

	return out
}

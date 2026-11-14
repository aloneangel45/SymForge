package xref

import (
	"encoding/hex"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

type x86Step struct {
	insnVA    uint64
	dataVA    uint64
	ptrReg    x86asm.Reg
	hasDataVA bool

	immVal     int64
	immReg     x86asm.Reg
	immMemBase x86asm.Reg
	immMemDisp int64
	hasImm     bool
	immIsMem   bool

	storeReg     x86asm.Reg
	storeMemBase x86asm.Reg
	storeMemDisp int64
	hasStore     bool
}

// canonicalX86Reg64 maps 8/16/32-bit general purpose registers to their 64-bit family (RAX..R15).
func canonicalX86Reg64(r x86asm.Reg) x86asm.Reg {
	switch {
	case x86asm.RAX <= r && r <= x86asm.R15:
		return r
	case x86asm.EAX <= r && r <= x86asm.R15L:
		return x86asm.RAX + (r - x86asm.EAX)
	case x86asm.AX <= r && r <= x86asm.R15W:
		return x86asm.RAX + (r - x86asm.AX)
	case x86asm.AL <= r && r <= x86asm.BL:
		return x86asm.RAX + (r - x86asm.AL)
	case x86asm.SPB <= r && r <= x86asm.R15B:
		return x86asm.RSP + (r - x86asm.SPB)
	default:
		return 0
	}
}

// goX86ABIPairedLenReg returns the next integer register in Go's x86_64 register ABI
// (RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11) used to pass string length alongside ptrReg.
func goX86ABIPairedLenReg(ptrReg x86asm.Reg) x86asm.Reg {
	switch ptrReg {
	case x86asm.RAX:
		return x86asm.RBX
	case x86asm.RBX:
		return x86asm.RCX
	case x86asm.RCX:
		return x86asm.RDI
	case x86asm.RDI:
		return x86asm.RSI
	case x86asm.RSI:
		return x86asm.R8
	case x86asm.R8:
		return x86asm.R9
	case x86asm.R9:
		return x86asm.R10
	case x86asm.R10:
		return x86asm.R11
	default:
		return 0
	}
}

func (a *analyzer) scanX86Function(fnIdx int, fnEntry uint64, code []byte, mode int) {
	steps := a.x86Scratch[:0]
	fnEnd := fnEntry + uint64(len(code))
	ptrSize := int64(a.lb.Info.PointerSize)
	if ptrSize != 4 && ptrSize != 8 {
		ptrSize = 8
	}

	off := 0
	for off < len(code) {
		inst, err := x86asm.Decode(code[off:], mode)
		if err != nil || inst.Len <= 0 {
			off++
			continue
		}
		insnVA := fnEntry + uint64(off)
		nextPC := insnVA + uint64(inst.Len)
		off += inst.Len

		var st x86Step
		st.insnVA = insnVA

		// 1. Direct and indirect CALL / tail JMP resolution.
		if inst.Op == x86asm.CALL || inst.Op == x86asm.JMP {
			switch a0 := inst.Args[0].(type) {
			case x86asm.Rel:
				targetVA := uint64(int64(nextPC) + int64(a0))
				if mode == 32 {
					targetVA &= 0xffffffff
				}
				if inst.Op == x86asm.CALL {
					a.recordCall(fnIdx, targetVA)
				} else if targetVA < fnEntry || targetVA >= fnEnd {
					// Tail JMP outside current function bounds.
					a.recordCall(fnIdx, targetVA)
				}
			case x86asm.Mem:
				if mode == 64 && a0.Base == x86asm.RIP && a0.Index == 0 {
					gotVA := uint64(int64(nextPC) + a0.Disp)
					if ptr, ok := a.lb.ReadPtrAtVA(gotVA); ok && ptr != 0 {
						a.recordCall(fnIdx, ptr)
					}
				} else if mode == 32 && a0.Base == 0 && a0.Index == 0 && a0.Disp != 0 {
					gotVA := uint64(uint32(a0.Disp))
					if ptr, ok := a.lb.ReadPtrAtVA(gotVA); ok && ptr != 0 {
						a.recordCall(fnIdx, ptr)
					}
				}
			}
			steps = append(steps, st)
			continue
		}

		// 2. RIP-relative (64-bit) or absolute disp (32-bit) data operand resolution.
		for argIdx := range inst.Args {
			arg := inst.Args[argIdx]
			if arg == nil {
				break
			}
			mem, ok := arg.(x86asm.Mem)
			if !ok {
				continue
			}
			if mode == 64 && mem.Base == x86asm.RIP && mem.Index == 0 {
				targetVA := uint64(int64(nextPC) + mem.Disp)
				st.dataVA = targetVA
				st.hasDataVA = true
				if argIdx == 1 {
					if r, isReg := inst.Args[0].(x86asm.Reg); isReg {
						st.ptrReg = canonicalX86Reg64(r)
					}
				}
				break
			} else if mode == 32 && mem.Base == 0 && mem.Index == 0 && mem.Disp != 0 {
				targetVA := uint64(uint32(mem.Disp))
				if a.lb.IsReadableVA(targetVA) && !a.lb.IsCodeVA(targetVA) {
					st.dataVA = targetVA
					st.hasDataVA = true
					if argIdx == 1 {
						if r, isReg := inst.Args[0].(x86asm.Reg); isReg {
							st.ptrReg = canonicalX86Reg64(r)
						}
					}
					break
				}
			}
		}

		// 3. Track MOV immediate loads (MOV reg, imm or MOV [base+disp], imm) and MOV [base+disp], reg
		// for 1-3 instruction window Go string (ptr, len) header reconstruction.
		if inst.Op == x86asm.MOV {
			if imm, isImm := inst.Args[1].(x86asm.Imm); isImm {
				val := int64(imm)
				if val >= 4 && val <= maxInsnSliceStrLen {
					switch dst := inst.Args[0].(type) {
					case x86asm.Reg:
						st.immVal = val
						st.immReg = canonicalX86Reg64(dst)
						st.hasImm = true
					case x86asm.Mem:
						if dst.Base != x86asm.RIP && dst.Index == 0 {
							st.immVal = val
							st.immMemBase = canonicalX86Reg64(dst.Base)
							st.immMemDisp = dst.Disp
							st.hasImm = true
							st.immIsMem = true
						}
					}
				}
			} else if srcReg, isSrcReg := inst.Args[1].(x86asm.Reg); isSrcReg {
				if dstMem, isDstMem := inst.Args[0].(x86asm.Mem); isDstMem && dstMem.Base != x86asm.RIP && dstMem.Index == 0 {
					st.storeReg = canonicalX86Reg64(srcReg)
					st.storeMemBase = canonicalX86Reg64(dstMem.Base)
					st.storeMemDisp = dstMem.Disp
					st.hasStore = true
				}
			}
		}

		steps = append(steps, st)
	}

	// Second micro-pass over decoded steps: check [-3, +3] instruction window around each RIP-relative reference.
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

		pairedReg := goX86ABIPairedLenReg(st.ptrReg)

		// Detect if ptrReg was stored to stack/struct slot [base + disp] within window.
		var hasPtrSlot bool
		var ptrSlotBase x86asm.Reg
		var ptrSlotDisp int64
		if st.ptrReg != 0 {
			for j := i + 1; j <= hi; j++ {
				if steps[j].hasStore && steps[j].storeReg == st.ptrReg {
					hasPtrSlot = true
					ptrSlotBase = steps[j].storeMemBase
					ptrSlotDisp = steps[j].storeMemDisp
					break
				}
			}
		}

		sliced := false
		// Pass A: exact ABI-paired register or adjacent memory slot [base + disp + ptrSize].
		for delta := 1; delta <= 3 && !sliced; delta++ {
			for _, j := range [2]int{i + delta, i - delta} {
				if j < lo || j > hi || !steps[j].hasImm {
					continue
				}
				cand := &steps[j]
				if !cand.immIsMem && pairedReg != 0 && cand.immReg == pairedReg {
					if a.strExt.trySliceInstructionString(st.dataVA, int(cand.immVal), true) {
						sliced = true
						break
					}
				}
				if cand.immIsMem && hasPtrSlot && cand.immMemBase == ptrSlotBase && cand.immMemDisp == ptrSlotDisp+ptrSize {
					if a.strExt.trySliceInstructionString(st.dataVA, int(cand.immVal), true) {
						sliced = true
						break
					}
				}
			}
		}

		// Pass B: fallback nearest MOV reg, imm in [-3, +3] (when not overwriting ptrReg itself).
		if !sliced {
			for delta := 1; delta <= 3 && !sliced; delta++ {
				for _, j := range [2]int{i + delta, i - delta} {
					if j < lo || j > hi || !steps[j].hasImm {
						continue
					}
					cand := &steps[j]
					if !cand.immIsMem && st.ptrReg != 0 && cand.immReg == st.ptrReg {
						continue
					}
					if a.strExt.trySliceInstructionString(st.dataVA, int(cand.immVal), false) {
						sliced = true
						break
					}
				}
			}
		}

		a.recordDataRef(fnIdx, st.insnVA, st.dataVA)
	}

	a.x86Scratch = steps[:0]
}

func disassembleX86(
	lb *loader.LoadedBinary,
	fn model.Function,
	code []byte,
	mode int,
	symMap map[uint64]string,
	strMap map[uint64]string,
	maxInsns int,
) []model.DisasmInstruction {
	out := make([]model.DisasmInstruction, 0, minIntVal(maxInsns, 128))
	off := 0
	unknownBounds := fn.Size == 0 && fn.End == 0

	for off < len(code) && len(out) < maxInsns {
		insnVA := fn.Entry + uint64(off)
		inst, err := x86asm.Decode(code[off:], mode)
		if err != nil || inst.Len <= 0 {
			out = append(out, model.DisasmInstruction{
				Addr:     insnVA,
				BytesHex: hex.EncodeToString(code[off : off+1]),
				Text:     "db 0x" + hex.EncodeToString(code[off:off+1]),
			})
			off++
			continue
		}

		if unknownBounds && len(out) > 0 && inst.Op == x86asm.INT && code[off] == 0xcc {
			break
		}

		rawBytes := code[off : off+inst.Len]
		nextPC := insnVA + uint64(inst.Len)
		off += inst.Len

		text := strings.ToLower(x86asm.IntelSyntax(inst, insnVA, nil))
		var targetVA uint64

		// Resolve relative branch/call targets first, then RIP-relative memory operands.
		for argIdx := range inst.Args {
			arg := inst.Args[argIdx]
			if arg == nil {
				break
			}
			switch v := arg.(type) {
			case x86asm.Rel:
				targetVA = uint64(int64(nextPC) + int64(v))
				if mode == 32 {
					targetVA &= 0xffffffff
				}
			case x86asm.Mem:
				if mode == 64 && v.Base == x86asm.RIP && v.Index == 0 {
					targetVA = uint64(int64(nextPC) + v.Disp)
				} else if mode == 32 && v.Base == 0 && v.Index == 0 && v.Disp != 0 {
					cand := uint64(uint32(v.Disp))
					if lb.IsReadableVA(cand) {
						targetVA = cand
					}
				}
			}
			if targetVA != 0 {
				break
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

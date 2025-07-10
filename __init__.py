#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#
import binaryninja
import sys
import json
from dataclasses import dataclass
from typing import Dict, List, Set, DefaultDict, Optional, Tuple
from collections import defaultdict
from enum import Enum


class Architecture(Enum):
    X86_64 = "x86_64"


class CommentPrefix(Enum):
    SOURCE = "src"
    DESTINATION = "dst"


@dataclass
class BranchData:
    module: str
    func: str
    registers: Dict[str, str]

    def get_reg_value(self, reg_name: str) -> int:
        return int(self.registers[reg_name], 16)

    def to_bv_abs_addr(self, reg_value: int, modules: Dict[str, int], bv: binaryninja.BinaryView) -> int:
        return (reg_value - modules[self.module]) + bv.start

    def get_reg_value_as_bv(self, reg_name: str, modules: Dict[str, int], bv: binaryninja.BinaryView) -> int:
        return self.to_bv_abs_addr(self.get_reg_value(reg_name), modules, bv)


class CommentManager:
    def __init__(self, bv: binaryninja.BinaryView):
        self.bv = bv
        self.comments_src: DefaultDict[int, Set[str]] = defaultdict(set)
        self.comments_dst: DefaultDict[int, Set[str]] = defaultdict(set)

    def add_source_comment(self, addr: int, comment: str) -> None:
        self.comments_src[addr].add(comment)

    def add_destination_comment(self, addr: int, comment: str) -> None:
        self.comments_dst[addr].add(comment)

    def set_comments(self) -> None:
        for prefix, comments in [
            (CommentPrefix.DESTINATION, self.comments_src),
            (CommentPrefix.SOURCE, self.comments_dst)
        ]:
            self._set_comments_for_prefix(comments, prefix)

    def _set_comments_for_prefix(self, comments: DefaultDict[int, Set[str]], prefix: CommentPrefix) -> None:
        for addr, comment_set in comments.items():
            joined_comment = f"BML_{prefix.value}: " + ", ".join(comment_set)
            existing_comment = self.bv.get_comment_at(addr)
            if existing_comment:
                joined_comment = f"{existing_comment}\n{joined_comment}"
            self.bv.set_comment_at(addr, joined_comment)


class BranchAnalyzer:
    def __init__(self, bv: binaryninja.BinaryView, modules: Dict[str, int]):
        self.bv = bv
        self.modules = modules
        self.comment_manager = CommentManager(bv)

    @staticmethod
    def get_memory_disp(tokens: List[str]) -> List[str]:
        operands = []
        start = False
        for token in tokens:
            if token.text == "[":
                start = True
                continue
            elif token.text == "]":
                start = False
                break
            if start:
                operands.append(token.text)
        return operands

    def get_func_name_at(self, addr: int) -> Optional[str]:
        func = self.bv.get_function_at(addr)
        if func is not None and not func.name.startswith("sub"):
            return func.name
        return None

    def get_func_name_containing(self, addr: int) -> Optional[str]:
        funcs = self.bv.get_functions_containing(addr)
        if funcs and not funcs[0].name.startswith("sub"):
            return funcs[0].name
        return None

    def analyze_branch(self, branch: Dict) -> None:
        before = BranchData(**branch["before"])
        after = BranchData(**branch["after"])

        src_addr = before.get_reg_value_as_bv("rip", self.modules, self.bv)
        
        if before.module == after.module:
            self._analyze_internal_branch(before, after, src_addr)
        else:
            self.comment_manager.add_source_comment(
                src_addr, f"<{after.module}>.{after.func}"
            )

    def _analyze_internal_branch(self, before: BranchData, after: BranchData, src_addr: int) -> None:
        if not self._validate_instruction(src_addr):
            return

        dst_addr = after.get_reg_value_as_bv("rip", self.modules, self.bv)
        self._add_branch_comments(before, src_addr, dst_addr)

    def _validate_instruction(self, addr: int) -> bool:
        instruction = self.bv.get_disassembly(addr)
        if instruction is None:
            print(f"Cannot get instruction @ {hex(addr)}", file=sys.stderr)
            return False
        if not instruction.startswith(("call", "jmp")):
            print(f"{instruction} @ {hex(addr)} is not an indirect branch instruction", file=sys.stderr)
            return False
        return True

    def _add_branch_comments(self, before: BranchData, src_addr: int, dst_addr: int) -> None:
        # Add source comments
        src_addr_comment = self._create_address_comment_for_src(dst_addr)
        src_addr_comment = self._add_vtable_info(before, src_addr, src_addr_comment)
        self.comment_manager.add_source_comment(src_addr, src_addr_comment)

        # Add destination comments
        dst_addr_comment = self._create_address_comment_for_dst(src_addr)
        self.comment_manager.add_destination_comment(dst_addr, dst_addr_comment)

    def _create_address_comment_for_src(self, addr: int) -> str:
        comment = hex(addr)
        if (func_name := self.get_func_name_at(addr)) is not None:
            comment += f"({func_name})"
        return comment

    def _create_address_comment_for_dst(self, addr: int) -> str:
        comment = hex(addr)
        if (func_name := self.get_func_name_containing(addr)) is not None:
            comment += f"({func_name})"
        return comment

    def _add_vtable_info(self, before: BranchData, src_addr: int, comment: str) -> str:
        llil = self.bv.arch.get_instruction_low_level_il_instruction(self.bv, src_addr)
        reg_and_imm = self.get_memory_disp(llil.operands[0].tokens)
        if reg_and_imm:
            reg_value = before.get_reg_value_as_bv(reg_and_imm[0], self.modules, self.bv)
            if (symbol := self.bv.get_symbol_at(reg_value)) is not None:
                comment += f" (vt:{hex(reg_value)}({symbol.name}))"
        return comment


def load(bv: binaryninja.BinaryView) -> None:
    if bv.arch.name != Architecture.X86_64.value:
        print("This plugin only supports x86_64 binaries", file=sys.stderr)
        return

    input_json = binaryninja.get_open_filename_input("filename:", "*.json")
    if input_json is None:
        print("Please specify a json file", file=sys.stderr)
        return
    
    try:
        with open(input_json, "r") as fin:
            raw_data = json.loads(fin.read())
            modules = {module["name"]: int(module["addr"], 16) for module in raw_data["modules"]}
            branches = raw_data["branches"]

        analyzer = BranchAnalyzer(bv, modules)
        for branch in branches:
            analyzer.analyze_branch(branch)
        
        analyzer.comment_manager.set_comments()

    except (json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"Error processing JSON file: {e}", file=sys.stderr)
        return


binaryninja.PluginCommand.register("Binja Missing Link", "Load branch tracking info", load)

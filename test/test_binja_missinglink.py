#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#
import os
import pytest
import sys
from typing import Dict

# Add parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import directly from __init__.py
from __init__ import (
    BranchData,
    BranchAnalyzer,
)

class TestBinjaMissingLink:
    @pytest.fixture
    def sample_branch_data(self) -> Dict:
        """Sample branch data for testing"""
        return {
            "modules": [
                {
                    "name": "main",
                    "addr": "0x100000000"
                },
                {
                    "name": "libtest_module",
                    "addr": "0x200000000"
                }
            ],
            "branches": [
                { # test for intra-module call thru func_table1
                    "before": {
                        "module": "main",
                        "func": "test_intra_module_call1",
                        "registers": {
                            "rip": "0x100000180", # Call module_func1 in test_intra_module_call1
                            "rax": "0x100000800"  # Thru func_table1
                        }
                    },
                    "after": {
                        "module": "main",
                        "func": "module_func1",
                        "registers": {
                            "rip": "0x100000200"
                        }
                    }
                },
                { # test for intra-module call thru func_table2 #1
                    "before": {
                        "module": "main",
                        "func": "test_intra_module_call2",
                        "registers": {
                            "rip": "0x100000480", # Call module_func1 in test_intra_module_call2
                            "rax": "0x100000900"  # Thru func_table2
                        }
                    },
                    "after": {
                        "module": "main",
                        "func": "module_func1",
                        "registers": {
                            "rip": "0x100000200"
                        }
                    }
                },
                { # test for inter-module call thru func_table2 #2
                    "before": {
                        "module": "main",
                        "func": "test_intra_module_call2",
                        "registers": {
                            "rip": "0x100000480", # Call module_func2 in test_intra_module_call2
                            "rax": "0x100001000"  # Thru func_table3
                        }
                    },
                    "after": {
                        "module": "main",
                        "func": "module_func2",
                        "registers": {
                            "rip": "0x100000500"
                        }
                    }
                },
                { # test for inter-module call
                    "before": {
                        "module": "main",
                        "func": "test_inter_module_call",
                        "registers": {
                            "rip": "0x100000380"
                        }
                    },
                    "after": {
                        "module": "libtest_module",
                        "func": "external_func1",
                        "registers": {
                            "rip": "0x200000100"
                        }
                    }
                },
                { # duplicated branch
                    "before": {
                        "module": "main",
                        "func": "test_intra_module_call2",
                        "registers": {
                            "rip": "0x100000480", # Call module_func1 in test_intra_module_call2
                            "rax": "0x100000900"  # Thru func_table2
                        }
                    },
                    "after": {
                        "module": "main",
                        "func": "module_func1",
                        "registers": {
                            "rip": "0x100000200"
                        }
                    }
                },
            ]
        }

    @pytest.fixture
    def mock_binary_view(self, monkeypatch):
        """Mock BinaryView for testing"""
        class MockArch:
            def __init__(self):
                self.name = "x86_64"

            def get_instruction_low_level_il_instruction(self, bv, addr):
                class MockLLIL:
                    def __init__(self, tokens):
                        self.operands = [type('Operand', (), {'tokens': tokens})()]
                if addr == 0x100000180:
                    return MockLLIL([
                        type('Token', (), {'text': '['})(),
                        type('Token', (), {'text': 'rax'})(),
                        type('Token', (), {'text': '+'})(),
                        type('Token', (), {'text': '0x10'})(),
                        type('Token', (), {'text': ']'})(),
                    ])
                elif addr == 0x100000380:
                    return MockLLIL([
                        type('Token', (), {'text': 'rax'})(),
                    ])
                elif addr == 0x100000480:
                    return MockLLIL([
                        type('Token', (), {'text': '['})(),
                        type('Token', (), {'text': 'rax'})(),
                        type('Token', (), {'text': '+'})(),
                        type('Token', (), {'text': '0x10'})(),
                        type('Token', (), {'text': ']'})(),
                    ])
                return None

        class MockBinaryView:
            def __init__(self):
                self.start = 0x100000000
                self.arch = MockArch()
                self._comments = {}
                self._functions = {
                    0x100000100: type('Function', (), {'name': 'test_intra_module_call1'})(),
                    0x100000200: type('Function', (), {'name': 'module_func1'})(),
                    0x100000300: type('Function', (), {'name': 'test_inter_module_call'})(),
                    0x100000400: type('Function', (), {'name': 'test_intra_module_call2'})(),
                    0x100000500: type('Function', (), {'name': 'module_func2'})(),
                    0x200000100: type('Function', (), {'name': 'external_func1'})(),
                }
                self._symbols = {
                    0x100000100: type('Symbol', (), {'name': 'test_intra_module_call1'})(),
                    0x100000200: type('Symbol', (), {'name': 'module_func1'})(),
                    0x100000300: type('Symbol', (), {'name': 'test_inter_module_call'})(),
                    0x100000400: type('Symbol', (), {'name': 'test_intra_module_call2'})(),
                    0x100000500: type('Symbol', (), {'name': 'module_func2'})(),
                    0x100000800: type('Symbol', (), {'name': 'func_table1'})(),
                    0x100000900: type('Symbol', (), {'name': 'func_table2'})(),
                    0x100001000: type('Symbol', (), {'name': 'func_table3'})(),
                    0x200000100: type('Symbol', (), {'name': 'external_func1'})(),
                }

            def get_function_at(self, addr: int):
                return self._functions.get(addr)

            def get_functions_containing(self, addr: int):
                for func_addr, func in self._functions.items():
                    if func_addr <= addr < func_addr + 0x100:
                        return [func]
                return []

            def get_comment_at(self, addr: int) -> str:
                return self._comments.get(addr, "")

            def set_comment_at(self, addr: int, comment: str) -> None:
                self._comments[addr] = comment

            def get_disassembly(self, addr: int) -> str:
                if addr == 0x100000180:
                    return "call [rax+0x10]"
                elif addr == 0x100000380:
                    return "call rax"
                elif addr == 0x100000480:
                    return "call [rax+0x10]"
                return None

            def get_symbol_at(self, addr: int):
                return self._symbols.get(addr)

        return MockBinaryView()

    def test_branch_data_parsing(self, sample_branch_data):
        """Test BranchData class parsing and methods"""
        branch = sample_branch_data["branches"][0]
        before = BranchData(**branch["before"])
        after = BranchData(**branch["after"])

        assert before.module == "main"
        assert before.func == "test_intra_module_call1"
        assert before.get_reg_value("rip") == 0x100000180
        assert before.get_reg_value("rax") == 0x100000800
        assert after.module == "main"
        assert after.func == "module_func1"
        assert after.get_reg_value("rip") == 0x100000200

    def test_get_memory_disp(self):
        """Test memory displacement parsing"""
        class MockToken:
            def __init__(self, text):
                self.text = text

        tokens = [
            MockToken("mov"),
            MockToken("["),
            MockToken("rax"),
            MockToken("+"),
            MockToken("0x10"),
            MockToken("]")
        ]

        result = BranchAnalyzer.get_memory_disp(tokens)
        assert result == ["rax", "+", "0x10"]

    def test_function_name_resolution(self, mock_binary_view):
        """Test function name resolution at addresses"""
        analyzer = BranchAnalyzer(mock_binary_view, {})
        
        # Test get_func_name_at
        func_name = analyzer.get_func_name_at(0x100000200)
        assert func_name == "module_func1"

        # Test get_func_name_containing
        func_name = analyzer.get_func_name_containing(0x100000250)
        assert func_name == "module_func1"

    def test_comment_generation_intra_module(self, mock_binary_view, sample_branch_data):
        """Test comment generation and setting"""
        modules = {
            module["name"]: int(module["addr"], 16) 
            for module in sample_branch_data["modules"]
        }
        analyzer = BranchAnalyzer(mock_binary_view, modules)

        # Test intra-module branch
        branch = sample_branch_data["branches"][0]
        analyzer.analyze_branch(branch)
        analyzer.comment_manager.set_comments()

        src_addr = int(branch["before"]["registers"]["rip"], 16)
        src_func_name = branch["before"]["func"]
        dst_addr = int(branch["after"]["registers"]["rip"], 16)
        dst_func_name = branch["after"]["func"]

        # Verify comments
        comment = mock_binary_view.get_comment_at(src_addr)
        assert f"BML_dst: {hex(dst_addr)}({dst_func_name})" in comment
        assert f"vt:{hex(0x100000800)}(func_table1)" in comment

        comment = mock_binary_view.get_comment_at(dst_addr)
        assert f"BML_src: {hex(src_addr)}({src_func_name})" in comment

    def test_comment_generation_inter_module(self, mock_binary_view, sample_branch_data):
        """Test comment generation and setting"""
        modules = {
            module["name"]: int(module["addr"], 16) 
            for module in sample_branch_data["modules"]
        }
        analyzer = BranchAnalyzer(mock_binary_view, modules)

        # Test inter-module branch
        branch = sample_branch_data["branches"][3]
        analyzer.analyze_branch(branch)
        analyzer.comment_manager.set_comments()

        src_addr = int(branch["before"]["registers"]["rip"], 16)
        dst_func_name = branch["after"]["func"]
        dst_module_name = branch["after"]["module"]

        # Verify comments
        comment = mock_binary_view.get_comment_at(src_addr)
        assert f"BML_dst: <{dst_module_name}>.{dst_func_name}" in comment

    def test_comment_generation_multiple_branches(self, mock_binary_view, sample_branch_data):
        """Test comment generation for multiple branches"""
        modules = {
            module["name"]: int(module["addr"], 16) 
            for module in sample_branch_data["modules"]
        }
        analyzer = BranchAnalyzer(mock_binary_view, modules)
        branches = sample_branch_data["branches"]
        for branch in branches:
            analyzer.analyze_branch(branch)
        analyzer.comment_manager.set_comments()

        comment = mock_binary_view.get_comment_at(0x100000200)
        assert f"BML_src:" in comment
        assert f"{hex(0x100000180)}(test_intra_module_call1)" in comment
        assert f"{hex(0x100000480)}(test_intra_module_call2)" in comment

        comment = mock_binary_view.get_comment_at(0x100000480)
        assert f"BML_dst:" in comment
        assert f"{hex(0x100000200)}(module_func1)" in comment
        assert f"vt:{hex(0x100000900)}(func_table2)" in comment
        assert f"{hex(0x100000500)}(module_func2)" in comment
        assert f"vt:{hex(0x100001000)}(func_table3)" in comment

    def test_invalid_instruction(self, mock_binary_view, sample_branch_data):
        """Test handling of invalid instructions"""
        # Modify the mock to return an invalid instruction
        def mock_get_disassembly(addr):
            return "nop"  # Not a call/jmp instruction

        mock_binary_view.get_disassembly = mock_get_disassembly

        # Process should continue without error, but skip the invalid instruction
        modules = {
            module["name"]: int(module["addr"], 16) 
            for module in sample_branch_data["modules"]
        }
        analyzer = BranchAnalyzer(mock_binary_view, modules)
        branch = sample_branch_data["branches"][0]
        analyzer.analyze_branch(branch)

        src_addr = BranchData(**branch["before"]).get_reg_value_as_bv(
            "rip", 
            modules,
            mock_binary_view
        )
        assert mock_binary_view.get_comment_at(src_addr) == "" 
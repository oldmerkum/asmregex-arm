"""
ghidra_loader.py

This module uses pyghidra to generate the disassembly from a given binary.

License:
    Author: oldmerkum [Antonio Marcum]
    Date: Apr 2026
"""

import os
import sys
import re
import pyghidra
from pathlib import Path

from asmregex import AssemblyInstruction, AssemblyList

def check_ghidra_install_dir(ghidra_install_dir):
    if not ghidra_install_dir:
        print("ERROR: GHIDRA_INSTALL_DIR environment variable not set")
        print("Please run: export GHIDRA_INSTALL_DIR='/path/to/ghidra/'")
        sys.exit(1)


class GhidraLoader:
    def __init__(self, binary_path):
        self.base_path = Path(__file__).resolve().parent.parent

        self.ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        check_ghidra_install_dir(self.ghidra_install_dir)
        
        self.binary_path = binary_path
        self.binary_base_name = os.path.basename(binary_path)
        
        self.ghidra_project_dir = str(self.base_path / ".ghidra_projects")
        self.ghidra_project_name = "asmregex-ghidra"

        os.makedirs(self.ghidra_project_dir, exist_ok=True)

        self.assemblies = []
        self.mappings = {}
    
    def get_all(self):
        pyghidra.start(install_dir=self.ghidra_install_dir)

        with pyghidra.open_project(self.ghidra_project_dir, self.ghidra_project_name, create=True) as project:
            root = project.projectData.getRootFolder()
            if not root.getFile(self.binary_base_name):
                with pyghidra.program_loader().project(project).source(self.binary_path).load() as results:
                    results.save(pyghidra.task_monitor())
            
            with pyghidra.program_context(project, f"/{self.binary_base_name}") as program:
                if not program.getOptions("Program Information").getBoolean("Analyzed", False):
                    pyghidra.analyze(program)
                    program.save(f"analyzed {self.binary_base_name}", pyghidra.task_monitor())
            
                self._process_instructions(program)
        return self.assemblies, self.mappings

    def _process_instructions(self, program):
        asmlist = AssemblyList()
        address_map = dict()
        count = 0

        listing = program.getListing()
        it = listing.getInstructions(program.getMinAddress(), True)

        for insn in it:
            mnemonic = insn.getMnemonicString()
            if not mnemonic: continue

            asm = AssemblyInstruction()
            asm['opcode'] = mnemonic
           
            num_operands = insn.getNumOperands()
            operand_list = []

            for i in range(num_operands):
                op_repr = insn.getDefaultOperandRepresentation(i)
                if op_repr:
                    operand_list.append(op_repr)
            op_str = ", ".join(operand_list)

            raw_args = re.split(r',(?![^\[\{]*[\]\}])', op_str)
            
            for raw_arg in raw_args:
                clean_arg = raw_arg.strip().replace('ptr', '')
                if clean_arg:
                    asm['args'].append(clean_arg)

            addr = insn.getAddress().getOffset()
            asm['addr'] = addr

            asmlist.append(asm)
            address_map[addr] = count
            count += 1
            # some manual debugging work
            #if 0x080eb6d0 <= asm['addr'] <= 0x080eb74e:
            #   print(f"{asm}: {asm['opcode']} {asm['args']}")


        self.assemblies = asmlist
        self.mappings = address_map

if __name__ == "__main__":
    import time
    if len(sys.argv) < 2:
        print("usage: python ghidra_loader.py <bin>")
        sys.exit(1)

    start_time = time.time()

    loader = GhidraLoader(sys.argv[1])
    ams, maps = loader.get_all()

    end_time = time.time()

    print(f"Executed in time: {end_time - start_time:.2f} seconds")

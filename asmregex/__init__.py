# global
import sys

# This is so it falls within the `asmregex' namespace already
from .Assembly import *  # many
from .PatternGenerator import PatternGenerator, MatchTableIterator  # all TODO: Remove when done, doesn't need to be in scope
from .PatternMatcher import AssemblyMatcher, AssemblyMatcherIterator  # All there is
from .PatternParser import PatternParser  # all
from .PatternPiece import *  # many

from .ghidra_loader import GhidraLoader

"""
Requirements for asmregex 2.0

PATTERN MATCHING:
- Context-dependent:
-> <mov,REGa,> <inc,REGa,> should match
->   mov eax, 2; inc eax
-> but not
->   mov eax, 2; inc ebx

-> For this, we need states when matching, new class. State saying reg['a'] = eax or reg['a'] = undef for example

- order agnostic:
- QUESTION: Is this really an issue? 
-> If one pattern would match
->   mov eax, 2; inc ebx
-> It should also match
->   inc ebx; mov eax, 2

-> Maybe the approach would be to give a list of instructions and their order
-> (if dependencies are known in the pattern):
->   <mov,REGa,0x12a,> <inc,REGa,> <lea,,REGa>
->   <xor,REGb,REGc,>  <lea,REGc,> <add,REGb,REGc,>

PATTERN GENERATION:
- Clear rules and systems
-> Obvious rules: abc, abC, ac should give
->   a b? lc=c
-> Complex rules: find out about the current situation

- Decide on additive approach or any-to-any approach (like the iterator right now)
- Make a repetition matching system
-> Rethink the system with LCS:
->   first-match on one would be naturally last-match on the other one
->   This may be useful when doing the additive approach
"""

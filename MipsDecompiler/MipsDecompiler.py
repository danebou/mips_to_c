
import ast
import attr
import re
import string

@attr.s(frozen=True)
class Register(object):
    register_name = attr.ib()

    def __str__(self):
        return '$%s' % (self.register_name,)

@attr.s(frozen=True)
class GlobalSymbol(object):
    symbol_name = attr.ib()

    def __str__(self):
        return '%s' % (self.symbol_name,)

@attr.s(frozen=True)
class Macro(object):
    macro_name = attr.ib()
    argument = attr.ib()

    def __str__(self):
        return '%%%s(%s)' % (self.macro_name, self.argument)

@attr.s(frozen=True)
class AddressMode(object):
    lhs = attr.ib()
    rhs = attr.ib()

    def __str__(self):
        if self.lhs is not None:
            return '%s(%s)' % (self.lhs, self.rhs)
        else:
            return '(%s)' % (self.rhs,)

@attr.s(frozen=True)
class NumberLiteral(object):
    value = attr.ib()

    def __str__(self):
        return hex(self.value)

@attr.s(frozen=True)
class BinOp(object):
    op = attr.ib()
    lhs = attr.ib()
    rhs = attr.ib()

    def __str__(self):
        return '%s %s %s' % (self.lhs, self.op, self.rhs)

@attr.s(frozen=True)
class JumpTarget(object):
    target = attr.ib()

    def __str__(self):
        return '.%s' % (self.target,)

valid_word = string.ascii_letters + string.digits + '_'
valid_number = '-x' + string.hexdigits

def parse_word(elems, valid=valid_word):
    S = ''
    while elems and elems[0] in valid:
        S += elems.pop(0)
    return S

def parse_number(elems):
    number_str = parse_word(elems, valid_number)
    return ast.literal_eval(number_str)

# Hacky parser.
def parse_arg_elems(arg_elems):
    value = None

    def expect(n):
        g = arg_elems.pop(0)
        if g not in n:
            print "WHOOPS", n, arg_elems
            XXX
        return g

    while arg_elems:
        tok = arg_elems[0]
        if tok.isspace():
            arg_elems.pop(0)
        elif tok == '$':
            assert value is None
            arg_elems.pop(0)
            value = Register(parse_word(arg_elems))
        elif tok == '.':
            assert value is None
            arg_elems.pop(0)
            value = JumpTarget(parse_word(arg_elems))
        elif tok == '%':
            assert value is None
            arg_elems.pop(0)
            macro_name = parse_word(arg_elems)
            assert macro_name in ('hi', 'lo')
            expect('(')
            m = parse_arg_elems(arg_elems)
            expect(')')
            return Macro(macro_name, m)
        elif tok == ')':
            break
        elif tok in ('-' + string.digits):
            # Try number.
            assert value is None
            value = NumberLiteral(parse_number(arg_elems))
        elif tok in '(':
            # Address mode.
            expect('(')
            rhs = parse_arg_elems(arg_elems)
            expect(')')
            value = AddressMode(value, rhs)
        elif tok in valid_word:
            # Global symbol.
            assert value is None
            value = GlobalSymbol(parse_word(arg_elems))
        elif tok in '>+&':
            # Binary operators.
            assert value is not None

            if tok == '>':
                expect('>')
                expect('>')
                op = '>>'
            else:
                op = expect('&+')

            rhs = parse_arg_elems(arg_elems)
            return BinOp(op, value, rhs)
        else:
            print tok, arg_elems
            XXX

    return value

def parse_arg(arg):
    arg_elems = list(arg)
    return parse_arg_elems(arg_elems)

@attr.s(frozen=True)
class Instruction(object):
    mnemonic = attr.ib()
    args = attr.ib()

    def is_branch_instruction(self):
        return self.mnemonic in ['b', 'bgez', 'bgtz', 'blez', 'bltz']

    def __str__(self):
        return '    %s %s' % (self.mnemonic, ', '.join(str(arg) for arg in self.args))

def parse_instruction(line):
    # First token is instruction name, rest is args.
    line = line.strip()
    mnemonic, _, args_str = line.partition(' ')
    # Parse arguments.
    args = [parse_arg(arg_str.strip()) for arg_str in args_str.split(',')]
    args = filter(None, args)
    return Instruction(mnemonic, args)

@attr.s(frozen=True)
class Label(object):
    name = attr.ib()

    def __str__(self):
        return '  .%s:' % (self.name, )

@attr.s
class Function(object):
    name = attr.ib()
    body = attr.ib(factory=list)

    def new_label(self, name):
        self.body.append(Label(name))

    def new_instruction(self, instruction):
        self.body.append(instruction)

    def __str__(self):
        return 'glabel %s\n%s' % (self.name, '\n'.join(str(item) for item in self.body))

@attr.s
class Program(object):
    filename = attr.ib()
    functions = attr.ib(factory=list)
    current_function = attr.ib(default=None, repr=False)

    def new_function(self, name):
        self.current_function = Function(name=name)
        self.functions.append(self.current_function)

    def new_instruction(self, instruction):
        self.current_function.new_instruction(instruction)

    def new_label(self, label):
        self.current_function.new_label(label)

    def __str__(self):
        return '# %s\n%s' % (self.filename, '\n\n'.join(str(function) for function in self.functions))

@attr.s(frozen=True)
class Block(object):
    index = attr.ib()
    label = attr.ib()
    instructions = attr.ib(factory=list)

    def __str__(self):
        if self.label:
            name = '%s (%s)' % (self.index, self.label.name)
        else:
            name = self.index
        return '# %s\n%s\n' % (name, '\n'.join(str(instruction) for instruction in self.instructions))

def is_loop_edge(node, edge):
    # Loops are represented by backwards jumps.
    return edge.block.index < node.block.index

@attr.s(frozen=True)
class BasicNode(object):
    block = attr.ib()
    exit_edge = attr.ib()

    def is_loop(self):
        return is_loop_edge(self, self.exit_edge)

    def __str__(self):
        return '%s\n# %d -> %d%s' % (self.block, self.block.index, self.exit_edge.block.index, ' (loop)' if self.is_loop() else '')

@attr.s(frozen=True)
class ExitNode(object):
    block = attr.ib()

    def __str__(self):
        return '%s\n# %d -> ret' % (self.block, self.block.index)

@attr.s(frozen=True)
class ConditionalNode(object):
    block = attr.ib()
    conditional_edge = attr.ib()
    fallthrough_edge = attr.ib()

    def is_loop(self):
        return is_loop_edge(self, self.conditional_edge)

    def __str__(self):
        return '%s\n# %d -> cond: %d%s, def: %s' % (self.block, self.block.index, self.conditional_edge.block.index, ' (loop)' if self.is_loop() else '', self.fallthrough_edge.block.index)

@attr.s(frozen=True)
class FlowAnalysis(object):
    nodes = attr.ib()

class box(object):
    pass

def do_flow_analysis(function):
    # Build blocks.
    blocks = []

    c = box()
    c.block_index = 0
    c.block_label = None
    c.instructions = []

    def new_block():
        if len(c.instructions) == 0:
            return
        block = Block(c.block_index, c.block_label, c.instructions)
        c.block_label = None
        c.block_index += 1
        blocks.append(block)
        c.instructions = []

    def take_instruction(instruction):
        c.instructions.append(instruction)

    body_iter = iter(function.body)
    for item in body_iter:
        if isinstance(item, Label):
            # Split blocks at labels.
            new_block()
            c.block_label = item
        elif isinstance(item, Instruction):
            take_instruction(item)
            if item.is_branch_instruction():
                # Handle delay slot. Take the next instruction before splitting body.
                take_instruction(next(body_iter))
                new_block()
    new_block()

    # Now build edges.
    exit_block = blocks[-1]
    exit_node = ExitNode(exit_block)
    nodes = [exit_node]

    def find_block_by_label(label):
        for block in blocks:
            if block.label and block.label.name == label.target:
                return block

    def get_block_analysis(block):
        for node in nodes:
            if node.block == block:
                return node
        node = do_block_analysis(block)
        nodes.append(node)
        return node

    def do_block_analysis(block):
        branch_instructions = [inst for inst in block.instructions if inst.is_branch_instruction()]

        if len(branch_instructions) == 0:
            # Fallthrough to next block index.
            exit_block = blocks[block.index + 1]
            exit_node = get_block_analysis(exit_block)
            return BasicNode(block, exit_node)
        elif len(branch_instructions) == 1:
            branch_instruction = branch_instructions[0]
            branch_label = branch_instruction.args[-1]
            branch_block = find_block_by_label(branch_label)
            assert branch_block is not None
            branch_node = get_block_analysis(branch_block)
            is_constant_branch = branch_instruction.mnemonic == 'b'
            if is_constant_branch:
                # If we have a constant branch, then we have a basic edge to our branch target.
                return BasicNode(block, branch_node)
            else:
                # If we have a conditional branch, then our fallthrough block is the next block.
                fallthrough_block = blocks[block.index + 1]
                fallthrough_node = get_block_analysis(fallthrough_block)
                return ConditionalNode(block, branch_node, fallthrough_node)
        else:
            # Shouldn't be possible.
            XXX

    entrance_block = blocks[0]
    get_block_analysis(entrance_block)
    nodes.sort(key=lambda node: node.block.index)
    return FlowAnalysis(nodes)

def decompile(filename, f):
    program = Program(filename)

    for line in f:
        # Strip comments and whitespace
        line = re.sub(r'/\*.*\*/', '', line)
        line = re.sub(r'#.*$', '', line)
        line = line.strip()

        if line == '':
            continue
        elif line.startswith('.') and line.endswith(':'):
            # Label.
            label_name = line.strip('.:')
            program.new_label(label_name)
        elif line.startswith('.'):
            # Assembler directive.
            pass
        elif line.startswith('glabel'):
            # Function label.
            function_name = line.split(' ')[1]
            program.new_function(function_name)
        else:
            # Instruction.
            instruction = parse_instruction(line)
            program.new_instruction(instruction)

    print program.functions[1]

    print "\n\n### FLOW ANALYSIS"
    flow_analysis = do_flow_analysis(program.functions[1])
    for node in flow_analysis.nodes:
        print node

def main():
    f = open('camera.s')
    decompile(f.name, f)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""Generate a Bradbury source artifact small enough for its transaction gas cap.

Public class/method/argument names and signatures, storage fields and their
annotations, prompt text and executable checks are preserved. Internal helper
annotations are omitted. The pinned minifier shortens internal
names and whitespace; run the full suite against both source and artifact.
Install requirements-dev.txt in a virtualenv to rebuild this artifact.
"""
import ast
import pathlib
import python_minifier

ROOT = pathlib.Path(__file__).resolve().parents[1]

class StripDocs(ast.NodeTransformer):
    def strip(self, node):
        self.generic_visit(node)
        if (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            node.body.pop(0)
        return node
    visit_Module = strip
    visit_ClassDef = strip
    def visit_FunctionDef(self, node):
        self.strip(node)
        # GenLayer consumes public signatures and storage field annotations.
        # Internal helpers/callbacks need neither annotation for dispatch.
        public = node.name == '__init__' or any(
            ast.unparse(decorator).startswith('gl.public.')
            for decorator in node.decorator_list
        )
        if not public:
            node.returns = None
            for argument in (*node.args.posonlyargs, *node.args.args,
                             *node.args.kwonlyargs):
                argument.annotation = None
            if node.args.vararg:
                node.args.vararg.annotation = None
            if node.args.kwarg:
                node.args.kwarg.annotation = None
        return node

source = (ROOT / 'contracts/attaint.py').read_text()
tree = StripDocs().visit(ast.parse(source))
public_args = []
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and (not node.name.startswith('_') or node.name == '__init__'):
        public_args.extend(arg.arg for arg in node.args.args)
output = source.splitlines()[0] + '\n' + python_minifier.minify(
    ast.unparse(tree), remove_annotations=False, remove_literal_statements=False,
    rename_globals=True, rename_locals=True, hoist_literals=True,
    preserve_globals=['Attaint', 'Policy', 'Attestation', 'Challenge', 'VERSION',
                      'gl', 'u32', 'u256', 'Address', 'TreeMap', 'DynArray',
                      'allow_storage', 'json', 'typing', 'dataclass'],
    preserve_locals=sorted(set(public_args)),
    remove_pass=False, combine_imports=False, remove_object_base=False,
    convert_posargs_to_args=False, remove_explicit_return_none=False,
    remove_builtin_exception_brackets=False, constant_folding=False,
) + '\n'
# SDK dispatch relies on public names and annotated call signatures.
def public_abi(module):
    contract = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == 'Attaint')
    return [(n.name, [a.arg for a in n.args.args]) for n in contract.body
            if isinstance(n, ast.FunctionDef) and not n.name.startswith('_')]
if public_abi(tree) != public_abi(ast.parse(output)):
    raise RuntimeError('Minification changed public method/argument names')
(ROOT / 'contracts/attaint.bradbury.py').write_text(output)
print('Deployment source: %d UTF-8 bytes; public ABI preserved.' % len(output.encode()))

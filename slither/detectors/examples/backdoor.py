from typing import List

from abc import ABC


from inspect import currentframe, getframeinfo
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from typing import Optional, List, Dict, Set, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import Node, NodeType
from slither.core.declarations.contract import Contract
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.core.declarations.structure import Structure
from slither.core.declarations.structure_contract import StructureContract
from slither.core.declarations.solidity_variables import SolidityVariable, SolidityFunction
from slither.core.variables.variable import Variable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.structure_variable import StructureVariable
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.literal import Literal
from slither.core.declarations.function_contract import FunctionContract
from slither.core.expressions.expression import Expression

from slither.core.expressions.tuple_expression import TupleExpression
from slither.core.expressions.literal import Literal
from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.type_conversion import TypeConversion
from slither.core.expressions.assignment_operation import AssignmentOperation
from slither.core.expressions.conditional_expression import ConditionalExpression
from slither.core.expressions.binary_operation import BinaryOperation, BinaryOperationType
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.index_access import IndexAccess
from slither.core.solidity_types.mapping_type import MappingType, Type
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.slithir.variables.temporary import TemporaryVariable
from slither.utils.function import get_function_id
import slither.analyses.data_dependency.data_dependency as data_dependency

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    SupportedOutput,
    Output,
)


from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract

from slither.core.declarations.structure import Structure
from slither.core.declarations.structure_contract import StructureContract
from slither.core.declarations.modifier import Modifier
from slither.core.variables.variable import Variable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.structure_variable import StructureVariable
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.literal import Literal
from slither.core.declarations.function_contract import FunctionContract

from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.type_conversion import TypeConversion
from slither.core.expressions.assignment_operation import AssignmentOperation
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.index_access import IndexAccess
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract
from slither.core.declarations.structure import Structure
from slither.core.variables.variable import Variable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.structure_variable import StructureVariable
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.literal import Literal
from slither.core.declarations.function_contract import FunctionContract

from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.type_conversion import TypeConversion
from slither.core.expressions.assignment_operation import AssignmentOperation
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.index_access import IndexAccess
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.slithir.operations import Call
from slither.slithir.operations import InternalCall
from slither.slithir.operations import SolidityCall
from slither.slithir.operations import HighLevelCall
from slither.slithir.operations import LowLevelCall
from slither.slithir.operations import Condition

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


class Backdoor(AbstractDetector):
    """
    Detect function named backdoor
    """

    ARGUMENT = "backdoor"  # slither will launch the detector with slither.py --mydetector
    HELP = "Function named backdoor (detector example)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/trailofbits/slither/wiki/Adding-a-new-detector"
    WIKI_TITLE = "Backdoor example"
    WIKI_DESCRIPTION = "Plugin example"
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    def _detect(self) -> List[Output]:
        results = []

        '''for contract in self.compilation_unit.contracts_derived:
                    # Check if a function has 'backdoor' in its name
                    for f in contract.functions:
                        if "digest" in f.name:
                            # Info to be printed
                            info: DETECTOR_INFO = ["digest function found in ", f, "\n"]

                            # Add the result in result
                            res = self.generate_result(info)

                            results.append(res)


                return results
                '''

        ecrecover_usage = False
        ecrecover_count = 0
        signature_validitycheck = False
        deadline_usage = False
        nonce_usage = False

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                for node in function.nodes:
                    #print(str(node.expression))
                    if "ecrecover" in str(node.expression):
                        ecrecover_usage = not ecrecover_usage
                        ecrecover_count = ecrecover_count + 1
                        A = node.function
                        print(A.name)
                        for ir in A.all_slithir_operations():
                            if isinstance(ir, Call):
                                print(ir)

                        info: DETECTOR_INFO = ["ecrecover found in function: ", A.name, "\n"]

                        # Add the result in result
                        res = self.generate_result(info)

                        results.append(res)

        return results



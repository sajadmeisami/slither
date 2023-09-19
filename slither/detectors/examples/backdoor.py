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
from slither.core.declarations.function import Function
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.declarations.function_contract import FunctionContract
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

    @staticmethod
    def _check_var_is_conditional(function, name_to_verify):
        conditional_node = None
        for operation in function.all_slithir_operations():
            if name_to_verify in str(operation.node.expression):
                conditional_node = operation.node
                variables_to_check = set(operation.node.variables_written)
                variables_checked = set()
                while variables_to_check:
                    ecrecover_var = variables_to_check.pop()
                    variables_checked.add(ecrecover_var)
                    for oper in function.all_slithir_operations():
                        if ecrecover_var.name in str(oper.node.expression):
                            variables_to_check.update(set(oper.node.variables_written) - variables_checked)
                            if oper.node.is_conditional():
                                conditional_node = oper.node
                                variables_to_check = set()  # We want to exit the while loop
                                break

        return conditional_node

    @staticmethod
    def _check_ecrecover_returning_value(funcs_that_calls_ecrecover_func):

        for func in funcs_that_calls_ecrecover_func:
            parameters = func.parameters
            ecrecover_conditional_node = Backdoor._check_var_is_conditional(func, "ecrecover")

            if ecrecover_conditional_node:
                # If we cannot find a conditional node inside the ecrecover function, it may be outside
                if not ecrecover_conditional_node.is_conditional():
                    functions_to_check = set(funcs_that_calls_ecrecover_func) - {func}
                    for function_checked in functions_to_check:
                        return_ecrecover_node = Backdoor._check_var_is_conditional(function_checked, func.name)
                        if return_ecrecover_node and return_ecrecover_node.is_conditional():
                            ecrecover_conditional_node = return_ecrecover_node
                            break

                for parameter in parameters:
                    # We check if the return value of ecrecover is compared to an address in parameter
                    # 'not in "uint8bytes32"' eliminates uint / uint8 / bytes / bytes32 type parameters
                    if str(parameter.type) not in "uint8bytes32" and str(parameter) in str(ecrecover_conditional_node.expression):
                        return True

        return False

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
                    # print(str(node.expression))
                    if "ecrecover" in str(node.expression):
                        ecrecover_usage = True
                        ecrecover_count += 1
                        ecrecover_func = node.function
                        print(ecrecover_func.name)

                        signature_validitycheck = True  # TODO: check “ecrecover” returning value (source) dependency on an address from one of the function parameters (PO: parameter owner) (sink) and not zero in conditional statement (If, require, bool)

                        # Get all the functions that call ecrecover_func
                        funcs_that_calls_ecrecover_func = set(ecrecover_func.all_reachable_from_functions).union({ecrecover_func})

                        signature_validitycheck = self._check_ecrecover_returning_value(funcs_that_calls_ecrecover_func)
                        print(signature_validitycheck)

                        # Get all the functions called by ecrecover_func excluding solidity ones
                        funcs_called_by_ecrecover_func = set(ecrecover_func.all_internal_calls()) - set(ecrecover_func.all_solidity_calls())
                        #solidity_func = ecrecover_func.all_solidity_calls()[0]
                        #print(solidity_func.full_name)
                        #print([el.to_json() for el in solidity_func.references])
                        #print([el.name for el in funcs_called_by_ecrecover_func])

                        fun = ecrecover_func.all_solidity_calls()[0]
                        #print(fun.name)
                        #print(fun.source_mapping)

                        funcs_to_inspect = funcs_that_calls_ecrecover_func.union(funcs_called_by_ecrecover_func)
                        funcs_inspected = set()

                        while funcs_to_inspect != set():
                            inspecting_func = funcs_to_inspect.pop()
                            funcs_inspected.add(inspecting_func)
                            #print(inspecting_func.name)
                            #print([(el.node.function.name, [par.name for par in el.node.function.parameters]) for el in inspecting_func.])
                            #for arg in inspecting_func.parameters:

                            # TODO: check inside the argument of keccak if there is deadline (link with block.timestamp/block.number/now) and nonce (depends on an address and is incrementable)



                            for operation in inspecting_func.all_slithir_operations():
                                if isinstance(operation, SolidityCall):
                                    #print(operation.node.expression)
                                    #print(operation.node.function.parameters)
                                    variable_to_check = set(operation.node.variables_read)
                                    variable_checked = set()
                                    while variable_to_check:
                                        deadline_nonce = variable_to_check.pop()
                                        variable_checked.add(deadline_nonce)
                                        if deadline_nonce in operation.node.function.parameters:
                                            #print(deadline.name)
                                            for oper in inspecting_func.all_slithir_operations():
                                                if deadline_nonce.name in str(oper.node.expression):
                                                    variable_to_check.update(set(oper.node.variables_read) - variable_checked)
                                                    if oper.node.is_conditional():
                                                        if "block.timestamp" in str(oper.node)\
                                                                or "block.number"in str(oper.node)\
                                                                or "now" in str(oper.node):
                                                            print(deadline_nonce.name)
                                                            variable_to_check = set()
                                                            break

                                        #else:
                                            #nonce

                            # Add the functions called by the function analyzed
                            # (functions that calls it are already added by "all_reachable_from_functions")
                            #funcs_called_by_inspecting_func = set(inspecting_func.all_internal_calls()) - set(inspecting_func.all_solidity_calls()) - funcs_inspected
                            #funcs_to_inspect.update(funcs_called_by_inspecting_func)

                        # for ir in A.all_slithir_operations():
                        #     if isinstance(ir, Call):
                        #         # print(ir)
                        #         if isinstance(ir, SolidityCall):
                        #             print(ir.function)
                        #             # if "ecrecover" in ir.function.name:
                        #             # print(ir.function)
                        #         elif isinstance(ir, InternalCall):
                        #             A_child = ir.function.nodes
                        #             # print(A_child)

                        info: DETECTOR_INFO = ["ecrecover found in function: ", ecrecover_func.name, "\n",
                                               f"ecrecover returning value dependency on an address from parameters: {signature_validitycheck}\n"]

                        # Add the result in result
                        res = self.generate_result(info)

                        results.append(res)

        return results

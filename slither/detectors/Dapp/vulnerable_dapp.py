from abc import ABC

import sha3
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
from slither.core.expressions.expression_typed import ExpressionTyped
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
import sha3
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification, SupportedOutput, Output
from slither.detectors.proxy.proxy_features import ProxyFeatureExtraction
from slither.utils.proxy_output import ProxyOutput
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract
from slither.core.children.child_contract import ChildContract
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
from slither.core.expressions.expression_typed import ExpressionTyped
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
from slither.core.expressions.expression_typed import ExpressionTyped
from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.type_conversion import TypeConversion
from slither.core.expressions.assignment_operation import AssignmentOperation
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.index_access import IndexAccess
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.solidity_types.elementary_type import ElementaryType

class ProxyPatterns(AbstractDetector, ABC):
    ARGUMENT = "proxy-patterns"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = "Proxy contract does not conform to any known standard"
    WIKI = "https://github.com/crytic/slither/wiki/Upgradeability-Checks#proxy-patterns"
    WIKI_TITLE = "Proxy Patterns"

    # region wiki_description
    WIKI_DESCRIPTION = """
Determine whether an upgradeable proxy contract conforms to any known proxy standards, i.e. OpenZeppelin, UUPS, Diamond 
Multi-Facet Proxy, etc.
"""
    # endregion wiki_description

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Proxy{
    address logicAddress;

    function() payable {
        logicAddress.delegatecall(msg.data)
    }
}

contract Logic{
    uint variable1;
}
```
The new version, `V2` does not contain `variable1`. 
If a new variable is added in an update of `V2`, this variable will hold the latest value of `variable2` and
will be corrupted.
"""
    # endregion wiki_exploit_scenario

    # region wiki_recommendation
    WIKI_RECOMMENDATION = """
It is better to use one of the common standards for upgradeable proxy contracts. Consider EIP-1967, EIP-1822, EIP-2523, 
or one of the proxy patterns developed by OpenZeppelin.
"""

    # endregion wiki_recommendation

    # region custom generate_result
    STANDARD_JSON = False

    """
    Override AbstractDetector.generate_result to define our own json output format
    """

    def generate_result(
            self,
            info: Union[str, List[Union[str, SupportedOutput]]],
            additional_fields: Optional[Dict] = None,
    ) -> ProxyOutput:
        contracts = [i for i in info if isinstance(i, Contract)]
        if len(contracts) > 0:
            contract = contracts[0]
        else:
            contract = None
        output = ProxyOutput(
            contract,
            info,
            additional_fields,
            standard_format=self.STANDARD_JSON,
            markdown_root=self.slither.markdown_root,
        )

        return output

    def verification_function(self):
        ecrecover_usage = False
        ecrecover_count = 0
        signature_validitycheck = False
        deadline_usage = False
        nonce_usage = False

        for contract in self.contracts:
            for function in contract.functions:
                for node in function.nodes:
                    if node.expression == 'ecrecover':
                        ecrecover_usage = not ecrecover_usage
                        ecrecover_count = ecrecover_count + 1
                        A = node.function
                        A_succ =
                        for function in A and A_succ:






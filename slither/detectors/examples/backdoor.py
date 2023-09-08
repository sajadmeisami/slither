from typing import List

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
                    print(node)
                    if node.expression == "ecrecover":
                        ecrecover_usage = not ecrecover_usage
                        ecrecover_count = ecrecover_count + 1
                        A = node.function
                        print(A.name)
                        info: DETECTOR_INFO = ["digest function found in ", f, "\n"]

                        # Add the result in result
                        res = self.generate_result(info)

                        results.append(res)

        return results



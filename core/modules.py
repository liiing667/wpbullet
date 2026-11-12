import re
import copy
from core import scanner
from core import taint

class BaseClass(object):

    # Vulnerability name
    name = ""

    # Vulnerability severity
    severity = ""

    # Functions causing vulnerability
    functions = []

    # Prefix before function causing vulnerability
    # (?<![^\s+(]) - negative lookahead allows only <nothing>, space and open brackets
    functions_prefix = r"(?<![^\s+(])"

    # Functions/regex that prevent exploitation
    blacklist = []

    # User-controlled variables
    user_input = taint.USER_INPUT

    # Finds vulnerabilities in given file content
    def run(self, content, file):
        content = taint.sanitize_content(content)
        pattern = self.build_pattern(self, content=content, file=file)
        matches = re.findall(pattern=pattern, string=content)
        return matches

    # Prints all found vulnerabilities
    def execute(self, content, file):
        matches = self.run(self, content, file)
        sanitized = taint.sanitize_content(content)
        original_lines = content.split('\n')
        for match in matches:
            if match[0]:
                line_no = self.get_match_line(sanitized, match[0])
                info = original_lines[line_no - 1].strip() if line_no else match[0]
                scanner.CODE_VULNERABILITIES.append([self.severity, self.name, file + ":" + str(line_no), info])

    # Build dynamic regex pattern to locate vulnerabilities in given content
    def build_pattern(self, content, file):
        user_input = copy.deepcopy(self.user_input)
        functions = copy.deepcopy(self.functions)

        variables = self.get_input_variables(self, content)

        if variables:
            user_input.extend(variables)

        if self.blacklist:
            blacklist_pattern = r"(?!(\s?)+(.*(" + '|'.join(self.blacklist) + ")))"
        else:
            blacklist_pattern = ""

        functions = [self.functions_prefix + x for x in functions]

        pattern = r"((" + '|'.join(functions) + ")\s{0,}\(\s{0,}" + blacklist_pattern + ".*(" + '|'.join(user_input) + ").*)"
        return pattern

    # Finds line in file on which vulnerability occurs
    @staticmethod
    def get_match_line(content, match):
        lineNo = 0
        for line in content.split('\n'):
            lineNo = lineNo + 1
            if match in line:
                return lineNo
        return False

    # Get variables which's content is possible to manipulate with user input
    # Lightweight scope-aware taint propagation over sanitized content
    def get_input_variables(self, content):
        return taint.get_tainted_variables(content, sources=self.user_input)

import unittest
from core import scanner
from core import taint
from Modules.CommandExecution import CommandExecution
from Modules.CrossSiteScripting import CrossSiteScripting
from Modules.SQLInjection import SQLInjection


class TestTaintPropagation(unittest.TestCase):

    def setUp(self):
        scanner.CODE_VULNERABILITIES[:] = [['Severity', 'Vulnerability', 'File', 'Info']]

    '''
    Assignment taint propagation (previously missed)
    '''
    # $_GET assigned to a variable, then used in a command sink
    def test_variable_assignment_to_command_sink(self):
        content = "<?php\n$cmd = $_GET['cmd'];\nsystem($cmd);\n"
        matches = CommandExecution.run(CommandExecution, content, "file.php")
        self.assertTrue(matches)

    # Taint through an array element
    def test_array_element_to_command_sink(self):
        content = "<?php\n$data['cmd'] = $_GET['cmd'];\nsystem($data['cmd']);\n"
        matches = CommandExecution.run(CommandExecution, content, "file.php")
        self.assertTrue(matches)

    # Taint through string concatenation into a SQL sink
    def test_string_concat_to_sql_sink(self):
        content = ("<?php\n"
                   "$query = \"SELECT * FROM users WHERE id = \" . $_GET['id'];\n"
                   "$wpdb->query($query);\n")
        matches = SQLInjection.run(SQLInjection, content, "file.php")
        self.assertTrue(matches)

    # Taint through concatenation assignment (.=)
    def test_concat_append_to_sql_sink(self):
        content = ("<?php\n"
                   "$query = \"SELECT * FROM users\";\n"
                   "$query .= \" WHERE id = \" . $_GET['id'];\n"
                   "$wpdb->query($query);\n")
        matches = SQLInjection.run(SQLInjection, content, "file.php")
        self.assertTrue(matches)

    # Taint through string interpolation into XSS sink
    def test_interpolated_variable_to_xss_sink(self):
        content = "<?php\n$out = $_GET['name'];\necho \"<p>$out</p>\";\n"
        matches = CrossSiteScripting.run(CrossSiteScripting, content, "file.php")
        self.assertTrue(matches)

    # Variable reassigned to a clean value is no longer tainted
    def test_reassignment_clears_taint(self):
        content = "<?php\n$out = $_GET['name'];\n$out = 'safe';\necho $out;\n"
        matches = CrossSiteScripting.run(CrossSiteScripting, content, "file.php")
        self.assertFalse(matches)

    # Taint inside a function does not clear the global scope taint
    def test_function_scope_isolation(self):
        content = ("<?php\n"
                   "$out = $_GET['name'];\n"
                   "function reset_out() {\n"
                   "    $out = 'safe';\n"
                   "}\n"
                   "echo $out;\n")
        matches = CrossSiteScripting.run(CrossSiteScripting, content, "file.php")
        self.assertTrue(matches)

    '''
    False positives in comments and strings (previously reported)
    '''
    # Sink inside a line comment is ignored
    def test_ignore_sink_in_line_comment(self):
        content = "<?php\n// system($_GET['cmd']);\n"
        matches = CommandExecution.run(CommandExecution, content, "file.php")
        self.assertFalse(matches)

    # Sink inside a block comment is ignored
    def test_ignore_sink_in_block_comment(self):
        content = "<?php\n/*\nsystem($_GET['cmd']);\n*/\n"
        matches = CommandExecution.run(CommandExecution, content, "file.php")
        self.assertFalse(matches)

    # Sink inside a hash comment is ignored
    def test_ignore_sink_in_hash_comment(self):
        content = "<?php\n# echo $_GET['name'];\n"
        matches = CrossSiteScripting.run(CrossSiteScripting, content, "file.php")
        self.assertFalse(matches)

    # Sink name inside a string literal is ignored
    def test_ignore_sink_in_string_literal(self):
        content = "<?php\n$help = \"Use system($_GET['cmd']) carefully\";\n"
        matches = CommandExecution.run(CommandExecution, content, "file.php")
        self.assertFalse(matches)

    # Trailing comment holding user input does not trigger a match
    def test_ignore_user_input_in_trailing_comment(self):
        content = "<?php\n$clean = 'x';\necho $clean; // echo $_GET['name']\n"
        matches = CrossSiteScripting.run(CrossSiteScripting, content, "file.php")
        self.assertFalse(matches)

    '''
    Conservative alerting when out of analyzable scope
    '''
    # extract() makes every variable potentially tainted
    def test_extract_triggers_conservative_taint(self):
        content = "<?php\nextract($_GET);\nsystem($cmd);\n"
        matches = CommandExecution.run(CommandExecution, content, "file.php")
        self.assertTrue(matches)

    # Heredoc content is kept verbatim so matches are not lost
    def test_heredoc_kept_verbatim(self):
        content = ("<?php\n"
                   "$cmd = $_GET['cmd'];\n"
                   "$x = <<<EOT\nsystem($cmd)\nEOT;\n")
        sanitized = taint.sanitize_content(content)
        self.assertIn("system($cmd)", sanitized)

    '''
    Line number format
    '''
    # Findings keep the file:line format and point at the sink line
    def test_line_number_format(self):
        content = ("<?php\n"
                   "// system($_GET['cmd']);\n"
                   "$cmd = $_GET['cmd'];\n"
                   "system($cmd);\n")
        CommandExecution.execute(CommandExecution, content, "file.php")
        self.assertEqual(len(scanner.CODE_VULNERABILITIES), 2)
        self.assertEqual(scanner.CODE_VULNERABILITIES[1][2], "file.php:4")

    def tearDown(self):
        scanner.CODE_VULNERABILITIES[:] = [['Severity', 'Vulnerability', 'File', 'Info']]

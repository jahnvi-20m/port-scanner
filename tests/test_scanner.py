import unittest

from scanner import parse_port_range


class TestPortRangeParsing(unittest.TestCase):

    def test_valid_range(self):
        ports = parse_port_range("20-22")
        self.assertEqual(list(ports), [20, 21, 22])

    def test_invalid_format(self):
        with self.assertRaises(ValueError):
            parse_port_range("20,22")

    def test_invalid_port_below_one(self):
        with self.assertRaises(ValueError):
            parse_port_range("0-10")

    def test_invalid_port_above_65535(self):
        with self.assertRaises(ValueError):
            parse_port_range("1-70000")

    def test_reversed_port_range(self):
        with self.assertRaises(ValueError):
            parse_port_range("100-10")


if __name__ == "__main__":
    unittest.main()
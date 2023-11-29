import re


def check_are_numbers(func):
    def is_numeric(expected_value, value):
        try:
            return func(int(expected_value), int(value))
        except (TypeError, ValueError):
            return False

    return is_numeric


@check_are_numbers
def is_less_than(maximum_value, value):
    return value < maximum_value


@check_are_numbers
def is_greater_than(minimum_value, value):
    return value > minimum_value


@check_are_numbers
def is_less_than_or_equal(maximum_value, value):
    return value <= maximum_value


@check_are_numbers
def is_greater_than_or_equal(minimum_value, value):
    return value >= minimum_value


def is_equal(expected_value, value):
    return value == expected_value


def is_not_equal(disallowed_value, value):
    return value != disallowed_value


def does_contain(expected_value, value):
    return bool(expected_value.lower() in value.lower())


def does_match_regex(regex_pattern, value):  # todo: parameterize case sensitivity
    return bool(re.search(regex_pattern, value, flags=re.IGNORECASE))

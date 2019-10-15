import sys
import pytest

forb_mod_scope = [
    'setup_module',
    'setup_function',
    'teardown_module',
    'teardown_function',
]

forb_cls_scope = [
    'setup_class',
    'setup_method',
    'teardown_class',
    'teardown_method',
]


def pytest_collection_finish(session):

    unit_test = sys.modules.get('unittest', None)
    unit_test_cls = getattr(unit_test, "TestCase", None)

    for item in session.items:
        cls = getattr(item, 'cls', None)
        subclassed = False
        if unit_test_cls is not None and cls is not None:
            subclassed = issubclass(cls, unit_test_cls)
        if subclassed:
            item.warn(pytest.PytestDeprecationWarning(
                "unittest is deprecated in favour of fixture style"))
            continue

        def xunit_depr_warn(item, attr, names):
            for n in names:
                obj = getattr(item, attr, None)
                method = getattr(obj, n, None)
                fixtured = hasattr(method, '__pytest_wrapped__')
                if method is not None and not fixtured:
                    item.warn(
                        pytest.PytestDeprecationWarning(
                            "xunit style is deprecated in favour of "
                            "fixture style"))

        xunit_depr_warn(item, 'module', forb_mod_scope)
        xunit_depr_warn(item, 'cls', forb_cls_scope)

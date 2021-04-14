from typing import Optional, List, Type, TypeVar
from _pytest.fixtures import FixtureRequest
from .config import Config, DomainDescriptionDict

MultihostFixture_T = TypeVar("MultihostFixture_T", bound=MultihostFixture)

class MultihostFixture:
    config: Config
    _pytestmh_request: FixtureRequest
    def __init__(self, config: Config, request: FixtureRequest) -> None: ...
    def install(self: MultihostFixture_T) -> MultihostFixture_T: ...

def make_multihost_fixture(
    request: FixtureRequest,
    descriptions: List[DomainDescriptionDict],
    config_class: Type[Config] = Config,
    _config: Optional[Config] = None,
) -> MultihostFixture: ...

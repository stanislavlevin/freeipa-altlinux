import abc
from typing import Any

class AsymmetricSignatureContext(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def update(self, data: Any) -> Any: ...
    @abc.abstractmethod
    def finalize(self) -> Any: ...

class AsymmetricVerificationContext(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def update(self, data: Any) -> Any: ...
    @abc.abstractmethod
    def verify(self) -> Any: ...

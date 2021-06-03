import abc

class KeyDerivationFunction(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def derive(self, key_material: bytes) -> bytes: ...
    @abc.abstractmethod
    def verify(self, key_material: bytes, expected_key: bytes) -> None: ...
